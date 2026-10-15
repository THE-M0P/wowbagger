"""engage watch — live terminal viewer for engage orchestrate/run.

Polls the engagement directory every 2 seconds and displays a Textual
dashboard: specialist progress, coordinator history, context pressure,
live findings, and a scrollable full-history activity log.

Scroll: trackpad / arrow keys / Page Up-Down.  f = follow tail.  q = quit.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Group
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, RichLog, Static


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_elapsed(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    return f"{m:02d}:{s:02d}"


def _truncate(text: str, maxlen: int) -> str:
    if len(text) <= maxlen:
        return text
    return text[: maxlen - 1] + "…"


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return events


def _find_all_audit_jsonls(engagement_dir: Path) -> list[Path]:
    found = []
    try:
        for p in engagement_dir.rglob("audit.jsonl"):
            found.append(p)
    except OSError:
        pass
    found.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0)
    return found


def _find_all_findings_sarifs(engagement_dir: Path) -> list[Path]:
    found = []
    try:
        for p in engagement_dir.rglob("findings.sarif"):
            found.append(p)
    except OSError:
        pass
    return found


def _count_findings(sarif_paths: list[Path]) -> dict[str, int]:
    confirmed = anomaly = lead = 0
    for p in sarif_paths:
        try:
            sarif = json.loads(p.read_text(encoding="utf-8"))
            results = sarif.get("runs", [{}])[0].get("results", [])
            for r in results:
                level = r.get("level", "")
                kind = r.get("kind", "")
                if kind == "pass":
                    continue
                if level in ("error", "warning"):
                    confirmed += 1
                elif level == "note":
                    anomaly += 1
                else:
                    lead += 1
        except (OSError, json.JSONDecodeError, IndexError, KeyError):
            pass
    return {"confirmed": confirmed, "anomaly": anomaly, "lead": lead}


def _load_chain_state(engagement_dir: Path) -> dict[str, Any]:
    p = engagement_dir / "chain-state.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def collect_state(engagement_dir: Path) -> dict[str, Any]:
    state: dict[str, Any] = {
        "engagement_dir": engagement_dir,
        "chain_state": {},
        "turn": 0,
        "max_turns": None,
        "context_pressure": 0.0,
        "compactions": 0,
        "thinking": False,
        "all_tools": [],
        "findings": {"confirmed": 0, "anomaly": 0, "lead": 0},
        "elapsed": 0,
        "current_run": None,
        "active_profile": None,
        "current_phase": None,
        "specialist_round": None,
        "status": "idle",
    }

    chain_state = _load_chain_state(engagement_dir)
    state["chain_state"] = chain_state

    started_at_str = chain_state.get("started_at")
    if started_at_str:
        try:
            start = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
            state["elapsed"] = int((datetime.now(timezone.utc) - start).total_seconds())
        except ValueError:
            pass

    sarifs = _find_all_findings_sarifs(engagement_dir)
    state["findings"] = _count_findings(sarifs)

    audit_files = _find_all_audit_jsonls(engagement_dir)
    if not audit_files:
        return state

    current_audit = audit_files[-1]
    run_dir = current_audit.parent.parent.parent
    state["current_run"] = str(run_dir.name)

    profile_files = list(run_dir.glob("*-profile.md"))
    if profile_files:
        state["active_profile"] = profile_files[0].stem.replace("-profile", "")

    m = re.match(r"run-(\d+)-(explore|audit)$", run_dir.name)
    if m:
        state["current_phase"] = "specialist" if m.group(2) == "explore" else "auditor"
        rounds_by = chain_state.get("rounds_by_specialist", {})
        exhausted_rounds = sum(rounds_by.values())
        explore_dirs = sum(
            1 for d in engagement_dir.iterdir()
            if re.match(r"run-\d+-explore$", d.name) and d.is_dir()
        )
        state["specialist_round"] = max(1, explore_dirs - exhausted_rounds)

    events = _read_jsonl(current_audit)
    if not events:
        return state

    llm_starts = [e for e in events if e.get("kind") == "llm_start"]
    llm_ends   = [e for e in events if e.get("kind") == "llm_end"]
    state["turn"] = len(llm_starts)

    scan_start = next((e for e in events if e.get("kind") == "scan_start"), None)
    if scan_start:
        state["max_turns"] = scan_start.get("max_turns")
        if not started_at_str:
            ts = scan_start.get("ts")
            if ts:
                try:
                    start = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    state["elapsed"] = int((datetime.now(timezone.utc) - start).total_seconds())
                except ValueError:
                    pass

    if llm_ends:
        state["context_pressure"] = llm_ends[-1].get("input_context_pressure", 0.0)

    state["compactions"] = sum(
        1 for e in events
        if e.get("kind") == "context_compaction_skip"
        and e.get("reason") == "no_summary_room"
    )

    last_event = events[-1]
    if last_event.get("kind") == "llm_start":
        state["thinking"] = True
    elif last_event.get("kind") == "scan_end":
        state["status"] = "done"

    tool_calls: list[dict[str, Any]] = []
    cur_turn = 0
    pending: dict[str, Any] | None = None
    for e in events:
        k = e.get("kind")
        if k == "llm_start":
            cur_turn = e.get("turn", cur_turn + 1)
        elif k == "tool_start":
            pending = {
                "turn": cur_turn,
                "tool": e.get("tool", "?"),
                "input": e.get("input_preview", {}).get("text", ""),
                "output": None,
                "duration_ms": None,
            }
        elif k == "tool_end" and pending is not None:
            pending["output"] = e.get("output_preview", {}).get("text", "")
            pending["duration_ms"] = e.get("duration_ms")
            tool_calls.append(pending)
            pending = None

    state["all_tools"] = tool_calls  # full history, no cap
    return state


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _pressure_style(pct: float) -> str:
    if pct >= 0.80:
        return "bold red"
    if pct >= 0.60:
        return "bold yellow"
    return "bold green"


def _clean_tool_output(out: str) -> str:
    out = re.sub(
        r'^Chunk ID: \S+\nWall time: [^\n]+\nProcess [^\n]+\nOutput:\n?',
        '', out, flags=re.MULTILINE,
    )
    out = re.sub(r'(?m)^[ \t]*[=\-]{4,}[ \t]*$', '', out)
    out = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', out)
    out = re.sub(r'[^\x09\x0a\x20-\x7e]', ' ', out)
    out = re.sub(r'\n{3,}', '\n\n', out)
    return out.strip()


def _fmt_duration(ms: int | None) -> str:
    if ms is None:
        return ""
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{ms}ms"


def _clean_exec_input(inp: str) -> str:
    cleaned = re.sub(
        r'^(?:\s*\w[\w_]*\s*\(\s*\)\s*\{(?:[^{}]|\{[^{}]*\})*\}\s*)+',
        '', inp, flags=re.DOTALL,
    ).strip()
    return cleaned if cleaned else inp


def _append_output(text: Text, out: str, max_lines: int = 8) -> None:
    lines = [ln for ln in out.splitlines() if ln.strip()]
    for line in lines[:max_lines]:
        text.append("  ")
        for part in re.split(r'\b(PASS|FAIL|ERROR|WARN)\b', line):
            if part == "PASS":
                text.append("PASS", style="bold green")
            elif part == "FAIL":
                text.append("FAIL", style="bold red")
            elif part in ("ERROR", "WARN"):
                text.append(part, style="bold yellow")
            elif re.match(r'^={2,}', part.strip()):
                text.append(part, style="dim italic")
            else:
                text.append(part, style="dim")
        text.append("\n")
    if len(lines) > max_lines:
        text.append(f"  … +{len(lines) - max_lines} more lines\n", style="dim")


# ---------------------------------------------------------------------------
# Rich renderables
# ---------------------------------------------------------------------------

def _render_status(state: dict[str, Any]) -> Any:
    chain_state    = state.get("chain_state", {})
    exhausted      = chain_state.get("exhausted", [])
    current        = chain_state.get("current")
    rounds_by      = chain_state.get("rounds_by_specialist", {})
    turn           = state.get("turn", 0)
    max_turns      = state.get("max_turns") or 120
    ctx_pct        = float(state.get("context_pressure") or 0.0)
    findings       = state.get("findings", {})
    elapsed        = state.get("elapsed", 0)
    thinking       = state.get("thinking", False)
    compactions    = state.get("compactions", 0)
    active_profile = state.get("active_profile")
    is_done        = state.get("status") == "done"

    status = Text()
    if chain_state:
        sp_count = len(exhausted) + (1 if current else 0)
        status.append(f"Specialist {sp_count}", style="dim")
        if current:
            status.append(": ")
            status.append(current, style="bold cyan")
    else:
        status.append("Run  ", style="dim")
        if active_profile:
            status.append(active_profile, style="bold cyan")

    if compactions:
        status.append(f"  compact×{compactions}", style="bold yellow")

    status.append("  Turn ", style="dim")
    status.append(str(turn), style="bold white")
    status.append(f"/{max_turns}", style="dim")

    status.append("  Context ", style="dim")
    bar_style = _pressure_style(ctx_pct)
    filled = int(ctx_pct * 16)
    status.append("█" * filled, style=bar_style)
    status.append("░" * (16 - filled), style="dim")
    status.append(f" {int(ctx_pct * 100)}%", style=bar_style)

    if is_done:
        status.append("  ✓ DONE", style="bold bright_green")
    elif thinking:
        status.append("  ⟳", style="bold yellow")

    status.append(f"  {_fmt_elapsed(elapsed)}", style="dim")

    conf = findings.get("confirmed", 0)
    anom = findings.get("anomaly", 0)
    lead = findings.get("lead", 0)

    if chain_state:
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        coord = Text()
        coord.append("COORDINATOR\n", style="bold white")
        for sp in exhausted:
            r = rounds_by.get(sp, "?")
            coord.append("✓ ", style="bold green")
            coord.append(f"{_truncate(sp, 22):<22} {r}r\n")
        if current:
            coord.append("→ ", style="bold yellow")
            coord.append(_truncate(current, 22), style="bold white")
            phase = state.get("current_phase", "")
            rnd = state.get("specialist_round")
            if rnd and phase:
                coord.append(f"  r{rnd}·{phase}", style="dim")
            elif phase:
                coord.append(f"  {phase}", style="dim")
            coord.append(f"  {turn}t\n", style="dim")

        finds = Text()
        finds.append("FINDINGS\n", style="bold white")
        finds.append("● ", style="bold red")
        finds.append("Confirmed  ")
        finds.append(str(conf), style="bold red" if conf else "bold white")
        finds.append("\n○ ", style="bold yellow")
        finds.append("Anomalies  ")
        finds.append(str(anom), style="bold yellow" if anom else "bold white")
        finds.append("\n◌ ", style="dim")
        finds.append("Leads      ")
        finds.append(str(lead), style="bold white")

        grid.add_row(coord, finds)
        mid: Any = grid
    else:
        mid = Text()
        mid.append("  ● ", style="bold red")
        mid.append("Confirmed ")
        mid.append(str(conf), style="bold red" if conf else "bold white")
        mid.append("   ○ ", style="bold yellow")
        mid.append("Anomalies ")
        mid.append(str(anom), style="bold yellow" if anom else "bold white")
        mid.append("   ◌ ", style="dim")
        mid.append(f"Leads {lead}", style="bold white")

    return Group(status, Rule(style="bright_black"), mid)


def _render_tool_call(tc: dict[str, Any]) -> Text:
    t_num  = tc.get("turn", "?")
    tool   = tc.get("tool", "?")
    inp    = (tc.get("input") or "").strip()
    out    = (tc.get("output") or "").strip()
    dur_ms = tc.get("duration_ms")

    if tool == "exec_command":
        try:
            parsed = json.loads(inp)
            inp = parsed.get("cmd", inp)
        except Exception:
            m = re.search(r'"cmd"\s*:\s*"((?:[^"\\]|\\.)*)', inp)
            if m:
                inp = m.group(1).replace("\\n", "\n").replace('\\"', '"')
        inp = _clean_exec_input(inp)

    if tool == "think":
        out = ""
    elif tool in ("create_todo", "update_todo", "complete_todo"):
        try:
            data = json.loads(out)
            todos = data.get("created") or data.get("updated") or []
            if todos:
                first = todos[0].get("title", "")
                extra = f" (+{len(todos) - 1} more)" if len(todos) > 1 else ""
                out = f"{first}{extra}"
            else:
                out = ""
        except Exception:
            pass
    elif out:
        out = _clean_tool_output(out)

    text = Text()
    text.append(f"T{t_num:<3} ", style="bold yellow")
    text.append(tool, style="bold cyan")
    if dur_ms is not None:
        text.append(f"  {_fmt_duration(dur_ms)}", style="dim")
    text.append("\n")

    if inp:
        inp_lines = inp.split("\n")
        text.append(f"  {inp_lines[0]}\n")
        for line in inp_lines[1:4]:
            if line.strip():
                text.append(f"  {line}\n", style="dim")

    if out:
        _append_output(text, out)

    text.append("\n")
    return text


# ---------------------------------------------------------------------------
# Textual app
# ---------------------------------------------------------------------------

class StatusPanel(Static):
    pass


class WatchApp(App):
    TITLE = "WOWBAGGER"

    CSS = """
    Screen {
        layout: vertical;
        background: $background;
    }
    StatusPanel {
        height: auto;
        padding: 0 1;
        background: $surface;
        border-bottom: heavy $primary-darken-3;
    }
    RichLog {
        height: 1fr;
        padding: 0 1;
        border: none;
        scrollbar-color: $primary-darken-2;
        scrollbar-color-hover: $primary;
    }
    Footer {
        background: $surface;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f", "follow", "Follow↓"),
        Binding("G", "follow", "Follow↓", show=False),
    ]

    def __init__(self, engagement_dir: Path, interval: int = 2) -> None:
        super().__init__()
        self.engagement_dir = engagement_dir
        self.interval = interval
        self._rendered_count = 0
        self._thinking_shown = False

    def compose(self) -> ComposeResult:
        yield StatusPanel()
        yield RichLog(highlight=False, markup=False, auto_scroll=True, wrap=True, id="log")
        yield Footer()

    def on_mount(self) -> None:
        self._tick()
        self.set_interval(self.interval, self._tick)

    def _tick(self) -> None:
        state = collect_state(self.engagement_dir)

        self.query_one(StatusPanel).update(_render_status(state))

        log = self.query_one(RichLog)
        all_tools = state.get("all_tools", [])
        new_count = len(all_tools)
        if new_count > self._rendered_count:
            for tc in all_tools[self._rendered_count:]:
                log.write(_render_tool_call(tc))
            self._rendered_count = new_count
            self._thinking_shown = False

        eng = self.engagement_dir.name
        run = state.get("current_run") or ""
        suffix = f" — {run}" if run and run != eng else ""
        self.title = f"WOWBAGGER  {eng}{suffix}"

        if state.get("thinking") and not self._thinking_shown:
            log.write(Text("⟳ Thinking…\n", style="bold yellow"))
            self._thinking_shown = True

    def action_follow(self) -> None:
        self.query_one(RichLog).scroll_end(animate=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_watch(args: argparse.Namespace) -> int:
    engagement_dir = Path(args.engagement).expanduser().resolve()
    if not engagement_dir.is_dir():
        print(f"engage watch: directory not found: {engagement_dir}")
        return 2

    interval = getattr(args, "interval", 2)
    WatchApp(engagement_dir, interval).run()
    return 0
