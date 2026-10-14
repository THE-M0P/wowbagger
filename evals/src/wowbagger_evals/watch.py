"""engage watch — live terminal viewer for engage orchestrate/run.

Polls the engagement directory every 2 seconds and redraws a compact
terminal dashboard showing: specialist progress, coordinator history,
context pressure, recent tool activity, and live findings.

No external dependencies — uses stdlib ANSI codes only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_RESET  = "\x1b[0m"
_BOLD   = "\x1b[1m"
_DIM    = "\x1b[2m"
_GREEN  = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED    = "\x1b[31m"
_CYAN   = "\x1b[36m"
_WHITE  = "\x1b[37m"
_BGREEN = "\x1b[1;32m"
_BYELLOW= "\x1b[1;33m"
_BRED   = "\x1b[1;31m"
_BCYAN  = "\x1b[1;36m"

CLEAR_SCREEN = "\x1b[2J\x1b[H"
HIDE_CURSOR  = "\x1b[?25l"
SHOW_CURSOR  = "\x1b[?25h"


def _c(text: str, *codes: str) -> str:
    return "".join(codes) + text + _RESET


def _bar(pct: float, width: int = 20) -> str:
    filled = int(pct * width)
    bar = "█" * filled + "░" * (width - filled)
    if pct >= 0.80:
        color = _BRED
    elif pct >= 0.60:
        color = _BYELLOW
    else:
        color = _BGREEN
    return color + bar + _RESET


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


def _visible_len(s: str) -> int:
    """Approximate visible character length, stripping ANSI escape sequences."""
    return len(re.sub(r"\x1b\[[0-9;]*m", "", s))


def _pad_to(text: str, width: int) -> str:
    """Pad text to visible width, accounting for ANSI escape codes."""
    return text + " " * max(0, width - _visible_len(text))


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
    """Return all audit.jsonl files under engagement_dir, sorted by mtime."""
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

    # Elapsed from chain-state started_at
    started_at_str = chain_state.get("started_at")
    if started_at_str:
        try:
            start = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
            state["elapsed"] = int((datetime.now(timezone.utc) - start).total_seconds())
        except ValueError:
            pass

    # Aggregate findings across all sarif files
    sarifs = _find_all_findings_sarifs(engagement_dir)
    state["findings"] = _count_findings(sarifs)

    # Find the most recently active audit.jsonl
    audit_files = _find_all_audit_jsonls(engagement_dir)
    if not audit_files:
        return state

    current_audit = audit_files[-1]
    state["current_run"] = str(current_audit.parent.parent.parent.name)  # run-NNN-explore

    events = _read_jsonl(current_audit)
    if not events:
        return state

    # Turn count and context pressure from llm events
    llm_starts = [e for e in events if e.get("kind") == "llm_start"]
    llm_ends   = [e for e in events if e.get("kind") == "llm_end"]
    state["turn"] = len(llm_starts)

    # Max turns from scan_start
    scan_start = next((e for e in events if e.get("kind") == "scan_start"), None)
    if scan_start:
        state["max_turns"] = scan_start.get("max_turns")
        # Fallback elapsed for engage run (no chain-state.json)
        if not started_at_str:
            ts = scan_start.get("ts")
            if ts:
                try:
                    start = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    state["elapsed"] = int((datetime.now(timezone.utc) - start).total_seconds())
                except ValueError:
                    pass

    if llm_ends:
        last_end = llm_ends[-1]
        state["context_pressure"] = last_end.get("input_context_pressure", 0.0)

    # Are we currently thinking? (last event is llm_start, no matching llm_end)
    if events:
        last_event = events[-1]
        if last_event.get("kind") == "llm_start":
            state["thinking"] = True
            state["thinking_since"] = last_event.get("ts")
        elif last_event.get("kind") == "scan_end":
            state["status"] = "done"

    # Tool calls with turn numbers — pending must be initialized before the loop
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

    state["recent_tools"] = tool_calls_with_turns[-12:]
    return state


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render(state: dict[str, Any], width: int | None = None) -> str:
    if width is None:
        width = shutil.get_terminal_size((100, 40)).columns
    width = max(60, min(width, 160))
    W = width
    inner = W - 2

    chain_state = state.get("chain_state", {})
    exhausted   = chain_state.get("exhausted", [])
    current     = chain_state.get("current")
    rounds_by   = chain_state.get("rounds_by_specialist", {})
    turn        = state.get("turn", 0)
    max_turns   = state.get("max_turns") or 120
    ctx_pct     = state.get("context_pressure", 0.0)
    findings    = state.get("findings", {})
    elapsed     = state.get("elapsed", 0)
    thinking    = state.get("thinking", False)
    recent      = state.get("recent_tools", [])
    current_run = state.get("current_run") or "—"
    eng_name    = state["engagement_dir"].name

    lines: list[str] = []

    def row(content: str = "", lc: str = "│", rc: str = "│") -> None:
        visible_len = _visible_len(content)
        pad = max(0, inner - visible_len)
        lines.append(lc + content + " " * pad + rc)

    def hline(lc: str = "├", rc: str = "┤", fill: str = "─", label: str = "") -> None:
        if label:
            label_part = f" {label} "
            remaining = inner - len(label_part)
            left_fill = remaining // 2
            right_fill = remaining - left_fill
            lines.append(lc + "─" * left_fill + label_part + "─" * right_fill + rc)
        else:
            lines.append(lc + fill * inner + rc)

    # Header
    sp_count = len(exhausted) + (1 if current else 0)
    header_left = f" {_c('WOWBAGGER', _BOLD, _CYAN)}  {_c(eng_name, _BOLD)}  {current_run}"
    header_right = f" {_c(_fmt_elapsed(elapsed), _BOLD)}  "
    header_mid_len = inner - _visible_len(header_left) - _visible_len(header_right)
    lines.append("┌" + "─" * inner + "┐")
    row(header_left + " " * max(0, header_mid_len) + header_right)
    hline()

    # Specialist + context bar row
    if chain_state:
        sp_label = f"Specialist {sp_count}"
        if current:
            sp_label = f"Specialist {sp_count}: {_c(current, _BOLD, _CYAN)}"
    else:
        sp_label = "Run"
    turn_part = f"  Turn {_c(str(turn), _BOLD)}/{max_turns}"
    ctx_bar = _bar(ctx_pct, 16)
    ctx_pct_str = f"{int(ctx_pct * 100)}%"
    if ctx_pct >= 0.80:
        ctx_pct_str = _c(ctx_pct_str, _BRED)
    elif ctx_pct >= 0.60:
        ctx_pct_str = _c(ctx_pct_str, _BYELLOW)
    ctx_part = f"  Context {ctx_bar} {ctx_pct_str}"
    row(f" {sp_label}{turn_part}{ctx_part}")
    hline()

    # COORDINATOR column (left half) + FINDINGS column (right half)
    col_w = (inner - 1) // 2
    right_w = inner - 1 - col_w

    def two_col(left: str, right: str) -> None:
        left_padded  = _pad_to(left,  col_w)
        right_padded = _pad_to(right, right_w)
        lines.append("│" + left_padded + "│" + right_padded + "│")

    def two_col_hline() -> None:
        lines.append("├" + "─" * col_w + "┼" + "─" * right_w + "┤")

    # Section headers
    two_col(
        _c(" COORDINATOR", _BOLD),
        _c(" FINDINGS", _BOLD),
    )
    two_col_hline()

    # Build coordinator rows — use _pad_to for ANSI-safe column alignment
    coord_rows: list[str] = []
    for sp in exhausted:
        r = rounds_by.get(sp, "?")
        marker = _c("✓", _BGREEN)
        name_padded = _pad_to(_truncate(sp, 18), 18)
        coord_rows.append(f" {marker} {name_padded} {r}r")
    if current:
        marker = _c("→", _BYELLOW)
        name_colored = _c(_truncate(current, 18), _BOLD)
        name_padded = _pad_to(name_colored, 18)
        coord_rows.append(f" {marker} {name_padded} {turn}t")

    # Build findings rows — color counts when non-zero
    conf = findings.get("confirmed", 0)
    anom = findings.get("anomaly", 0)
    lead = findings.get("lead", 0)
    conf_str = _c(str(conf), _BRED)   if conf > 0 else _c(str(conf), _BOLD)
    anom_str = _c(str(anom), _BYELLOW) if anom > 0 else _c(str(anom), _BOLD)
    lead_str = _c(str(lead), _BOLD)
    find_rows = [
        f" {_c('●', _BRED)} Confirmed  {conf_str}",
        f" {_c('○', _BYELLOW)} Anomalies  {anom_str}",
        f" {_c('◌', _DIM)} Leads      {lead_str}",
    ]

    n_rows = max(len(coord_rows), len(find_rows), 2)
    for i in range(n_rows):
        l = coord_rows[i] if i < len(coord_rows) else ""
        r = find_rows[i] if i < len(find_rows) else ""
        two_col(l, r)

    hline(label="ACTIVITY")

    # How many tool-call pairs fit in the remaining terminal height
    term_h = shutil.get_terminal_size((100, 40)).lines
    fixed_rows = 3 + 2 + 2 + n_rows + 2  # header+sep, specialist, col headers+sep, col rows, activity sep+footer
    available_rows = max(4, term_h - fixed_rows - (1 if thinking else 0))
    max_tc = max(1, available_rows // 2)  # each tool call takes ~2 lines (cmd + output)

    # Activity feed
    activity_rows: list[str] = []
    if thinking:
        activity_rows.append(f" {_c('⟳', _BYELLOW)} {_c('Thinking…', _BOLD, _YELLOW)}")

    for tc in reversed(recent[-max_tc:]):
        t_num   = tc.get("turn", "?")
        tool    = tc.get("tool", "?")
        inp     = (tc.get("input") or "").replace("\n", " ").strip()
        out     = (tc.get("output") or "").replace("\n", " ").strip()
        dur_ms  = tc.get("duration_ms")

        # Extract command from exec_command input JSON
        if tool == "exec_command":
            try:
                parsed = json.loads(inp)
                inp = parsed.get("cmd", inp).split("\n")[0]
            except Exception:
                pass

        # Strip strix output metadata: "Chunk ID: X Wall time: X.X seconds Process exited with code X Output: <actual>"
        if out:
            m = re.search(r'Output: (.+)', out)
            if m:
                out = m.group(1)

        dur_str = f" ({dur_ms}ms)" if dur_ms is not None else ""
        tool_colored = _c(tool, _CYAN)
        inp_avail = inner - 2 - 5 - 2 - _visible_len(tool) - 2 - len(dur_str)
        inp_truncated = _truncate(inp, max(20, inp_avail))
        activity_rows.append(f" T{t_num:<3} {tool_colored}  {inp_truncated}{_c(dur_str, _DIM)}")

        if out:
            out_clean = _truncate(out, inner - 9)
            activity_rows.append(f"      {_c('→', _DIM)} {_c(out_clean, _DIM)}")

    if not activity_rows:
        activity_rows = [_c(" (waiting for first turn…)", _DIM)]

    for ar in activity_rows:
        row(" " + ar if not ar.startswith(" ") else ar)

    lines.append("└" + "─" * inner + "┘")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_watch(args: argparse.Namespace) -> int:
    engagement_dir = Path(args.engagement).expanduser().resolve()
    if not engagement_dir.is_dir():
        print(f"engage watch: directory not found: {engagement_dir}", file=sys.stderr)
        return 2

    interval = getattr(args, "interval", 2)

    sys.stdout.write(HIDE_CURSOR)
    sys.stdout.flush()
    try:
        while True:
            state = collect_state(engagement_dir)
            width = shutil.get_terminal_size((100, 40)).columns
            out = CLEAR_SCREEN + render(state, width) + "\n"
            sys.stdout.write(out)
            sys.stdout.flush()

            if state.get("status") == "done":
                print(_c("\n  Run complete.", _BGREEN))
                return 0

            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()
        print()
    return 0
