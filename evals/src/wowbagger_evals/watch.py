"""engage watch — live terminal viewer for engage orchestrate/run.

Polls the engagement directory every 2 seconds and redraws a compact
terminal dashboard showing: specialist progress, coordinator history,
context pressure, recent tool activity, and live findings.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text


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
        "thinking_since": None,
        "recent_tools": [],
        "findings": {"confirmed": 0, "anomaly": 0, "lead": 0},
        "elapsed": 0,
        "current_run": None,
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
    else:
        state["active_profile"] = None

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

    if events:
        last_event = events[-1]
        if last_event.get("kind") == "llm_start":
            state["thinking"] = True
            state["thinking_since"] = last_event.get("ts")
        elif last_event.get("kind") == "scan_end":
            state["status"] = "done"

    tool_calls_with_turns: list[dict[str, Any]] = []
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
            tool_calls_with_turns.append(pending)
            pending = None

    state["recent_tools"] = tool_calls_with_turns[-40:]
    return state


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _pressure_style(pct: float) -> str:
    if pct >= 0.80:
        return "bold red"
    if pct >= 0.60:
        return "bold yellow"
    return "bold green"


def _clean_tool_output(out: str) -> str:
    m = re.search(r'Output: (.+)', out)
    if m:
        out = m.group(1)
    out = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', out)
    out = re.sub(r'[^\x20-\x7e]', ' ', out)
    return out.replace('\t', ' ').strip()


def _fmt_duration(ms: int | None) -> str:
    if ms is None:
        return ""
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{ms}ms"


def _clean_exec_input(inp: str) -> str:
    """Strip leading bash helper function definitions (ok/fail/check_json etc.)."""
    cleaned = re.sub(
        r'^(?:\s*\w[\w_]*\s*\(\s*\)\s*\{(?:[^{}]|\{[^{}]*\})*\}\s*)+',
        '', inp, flags=re.DOTALL,
    ).strip()
    return cleaned if cleaned else inp


def _append_output(text: Text, out: str, avail: int) -> None:
    """Append tool output, coloring PASS bold-green and FAIL bold-red."""
    for part in re.split(r'\b(PASS|FAIL)\b', _truncate(out, avail)):
        if part == "PASS":
            text.append("PASS", style="bold green")
        elif part == "FAIL":
            text.append("FAIL", style="bold red")
        else:
            text.append(part, style="dim")


def make_renderable(state: dict[str, Any], term_height: int = 40, term_width: int = 120) -> Panel:
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
    recent         = state.get("recent_tools", [])
    current_run    = state.get("current_run") or ""
    active_profile = state.get("active_profile")
    eng_name       = state["engagement_dir"].name
    is_done        = state.get("status") == "done"

    # --- Panel title ---
    title = Text()
    title.append("WOWBAGGER", style="bold cyan")
    title.append(f"  {eng_name}", style="bold white")
    if current_run and current_run != eng_name:
        title.append(f"  {current_run}", style="dim")

    # --- Status line ---
    status = Text(justify="left")
    sp_count = len(exhausted) + (1 if current else 0)
    if chain_state:
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
    status.append(" ")
    status.append(f"{int(ctx_pct * 100)}%", style=bar_style)

    # --- Coordinator + findings / single findings ---
    conf = findings.get("confirmed", 0)
    anom = findings.get("anomaly", 0)
    lead = findings.get("lead", 0)

    if chain_state:
        mid_table = Table.grid(expand=True, padding=(0, 1))
        mid_table.add_column(ratio=1)
        mid_table.add_column(ratio=1)

        coord = Text()
        coord.append("COORDINATOR\n", style="bold white")
        for sp in exhausted:
            r = rounds_by.get(sp, "?")
            coord.append("✓ ", style="bold green")
            coord.append(f"{_truncate(sp, 22):<22} {r}r\n")
        if current:
            coord.append("→ ", style="bold yellow")
            coord.append(_truncate(current, 22), style="bold white")
            coord.append(f"  {turn}t\n", style="dim")

        finds = Text()
        finds.append("FINDINGS\n", style="bold white")
        finds.append("● ", style="bold red")
        finds.append("Confirmed  ")
        finds.append(str(conf), style="bold red" if conf else "bold white")
        finds.append("\n")
        finds.append("○ ", style="bold yellow")
        finds.append("Anomalies  ")
        finds.append(str(anom), style="bold yellow" if anom else "bold white")
        finds.append("\n")
        finds.append("◌ ", style="dim")
        finds.append("Leads      ")
        finds.append(str(lead), style="bold white")

        mid_table.add_row(coord, finds)
        mid_section: Any = mid_table
    else:
        mid_section = Text(justify="left")
        mid_section.append("  ● ", style="bold red")
        mid_section.append("Confirmed ")
        mid_section.append(str(conf), style="bold red" if conf else "bold white")
        mid_section.append("   ○ ", style="bold yellow")
        mid_section.append("Anomalies ")
        mid_section.append(str(anom), style="bold yellow" if anom else "bold white")
        mid_section.append("   ◌ ", style="dim")
        mid_section.append("Leads ")
        mid_section.append(str(lead), style="bold white")

    # --- Activity feed ---
    # 3 lines per entry: header + output + blank separator
    reserved = 10 + (len(exhausted) + (1 if current else 0) if chain_state else 0)
    max_tc = max(2, (term_height - reserved) // 3)
    # usable width: panel borders (2) + Rich padding (4) + left gutter (~6)
    avail = max(40, term_width - 12)

    activity = Text(justify="left")
    if thinking:
        activity.append("⟳ Thinking…\n\n", style="bold yellow")

    shown = list(reversed(recent[-max_tc:]))
    for tc in shown:
        t_num  = tc.get("turn", "?")
        tool   = tc.get("tool", "?")
        inp    = (tc.get("input") or "").replace("\n", " ").strip()
        out    = (tc.get("output") or "").replace("\n", " ").strip()
        dur_ms = tc.get("duration_ms")

        if tool == "exec_command":
            try:
                parsed = json.loads(inp)
                inp = parsed.get("cmd", inp).split("\n")[0]
            except Exception:
                m = re.search(r'"cmd"\s*:\s*"((?:[^"\\]|\\.)*)', inp)
                if m:
                    inp = m.group(1).replace("\\n", " ").replace('\\"', '"')
            inp = _clean_exec_input(inp)

        if out:
            out = _clean_tool_output(out)

        dur_str = _fmt_duration(dur_ms)

        # Header: T11  toolname  1.5s  command...
        activity.append(f"T{t_num:<3} ", style="dim")
        activity.append(tool, style="bold cyan")
        if dur_str:
            activity.append(f"  {dur_str}", style="dim")
        activity.append(f"  {_truncate(inp, avail)}\n")

        # Output line with PASS/FAIL coloring
        if out:
            activity.append("  → ", style="dim")
            _append_output(activity, out, avail)
            activity.append("\n")

        activity.append("\n")  # blank line between entries

    if not shown and not thinking:
        activity.append("(waiting for first turn…)", style="dim")

    content = Group(
        status,
        Rule(style="bright_black"),
        mid_section,
        Rule("ACTIVITY", style="bright_black"),
        activity,
    )

    border = "bright_green" if is_done else "bright_cyan"
    subtitle = Text(_fmt_elapsed(elapsed), style="bold white")

    return Panel(content, title=title, subtitle=subtitle, border_style=border, height=term_height)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_watch(args: argparse.Namespace) -> int:
    engagement_dir = Path(args.engagement).expanduser().resolve()
    if not engagement_dir.is_dir():
        print(f"engage watch: directory not found: {engagement_dir}")
        return 2

    interval = getattr(args, "interval", 2)
    console = Console()

    state = collect_state(engagement_dir)
    term_h = console.height

    with Live(
        make_renderable(state, term_h, console.width),
        console=console,
        screen=True,
        refresh_per_second=4,
    ) as live:
        try:
            while True:
                state = collect_state(engagement_dir)
                term_h = console.height
                live.update(make_renderable(state, term_h, console.width))

                if state.get("status") == "done":
                    time.sleep(1)
                    break

                time.sleep(interval)
        except KeyboardInterrupt:
            pass

    return 0
