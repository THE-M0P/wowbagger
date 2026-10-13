"""engage.py — Automated multi-round security testing chain runner.

Runs explore→audit rounds sequentially, stopping on consecutive dry runs
or when the round limit is reached. Notifies on completion.

Modes:
  whitebox  White-box target: source code + running container (BountyBench)
  target    Black-box URL target: live app, H1 program, CTF box, lab VM

Usage:
  engage run --project lunary \\
      --engagement ~/wowbagger-runs/engagements/lunary/chain-002 \\
      --rounds 5 --stop-on-dry-runs 2

  engage run --mode target --target https://app.example.com \\
      --instructions ~/programs/example/instructions.md \\
      --engagement ~/wowbagger-runs/engagements/example/chain-001 \\
      --max-rounds 10 --stop-on-dry-runs 2

See docs/runbooks/engage-pipeline-plan.md for full design.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from wowbagger_evals.watch import run_watch
from wowbagger_evals.bountybench import (
    BountyBenchError,
    build_plan,
    collect_engagement_artifacts,
    execute_plan,
    load_task,
    now_iso,
    stage_engagement,
    write_audit_profile,
    write_plan,
)
from wowbagger_evals.config import (
    STRIX_BIN as _STRIX_DEFAULT,
    BOUNTYBENCH_DIR as _BOUNTYBENCH_DEFAULT,
    SPECIALIST_PACK as _DEFAULT_SPECIALIST_PACK,
    TARGET_SPECIALIST_PACK as _TARGET_SPECIALIST_PACK,
    SMOKE_SPECIALIST_PACK as _SMOKE_SPECIALIST_PACK,
    SANDBOX_IMAGE as _SANDBOX_IMAGE_DEFAULT,
    LLM as _LLM_DEFAULT,
    LLM_API_BASE as _LLM_API_BASE_DEFAULT,
    LLM_API_KEY as _LLM_API_KEY_DEFAULT,
    CONTEXT_WINDOW as _CONTEXT_WINDOW_DEFAULT,
    DISABLE_STREAMING as _DISABLE_STREAMING_DEFAULT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"[engage] {msg}", flush=True)


def _notify(title: str, body: str, enabled: bool) -> None:
    if not enabled:
        return
    subprocess.run(
        ["notify-send", "-a", "engage", "-t", "15000", title, body],
        check=False,
    )


def _next_run_number(engagement_dir: Path) -> int:
    """Scan existing run-NNN-explore dirs to get the next run number."""
    max_n = 0
    if engagement_dir.is_dir():
        for d in engagement_dir.iterdir():
            if d.is_dir():
                m = re.match(r"run-(\d+)-explore$", d.name)
                if m:
                    max_n = max(max_n, int(m.group(1)))
    return max_n + 1


def _is_dry_run(engagement_dir: Path) -> bool:
    """True if the latest explore produced no [pending-audit] findings or anomalies."""
    additions = engagement_dir / "run-additions.md"
    if not additions.is_file():
        return False
    return "[pending-audit]" not in additions.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# BountyBench target container lifecycle
# ---------------------------------------------------------------------------

def _compose_file(task_dir: Path) -> Path | None:
    p = task_dir / "docker-compose.yml"
    return p if p.is_file() else None


def _start_target(task_dir: Path) -> bool:
    """Start the BountyBench target container via docker compose. Returns True on success."""
    compose = _compose_file(task_dir)
    if compose is None:
        _log(f"auto-start: no docker-compose.yml in {task_dir} — skipping")
        return False
    _log(f"auto-start: docker compose up -d  ({compose.parent.name})")
    r = subprocess.run(
        ["docker", "compose", "-f", str(compose), "up", "-d", "--wait"],
        cwd=task_dir,
        check=False,
    )
    if r.returncode != 0:
        _log(f"auto-start: docker compose up failed (rc={r.returncode})")
        return False
    _log("auto-start: target container started")
    return True


def _stop_target(task_dir: Path) -> None:
    compose = _compose_file(task_dir)
    if compose is None:
        return
    _log(f"auto-stop: docker compose down  ({compose.parent.name})")
    subprocess.run(
        ["docker", "compose", "-f", str(compose), "down"],
        cwd=task_dir,
        check=False,
    )
    _log("auto-stop: target container stopped")


# ---------------------------------------------------------------------------
# Whitebox mode: delegate to existing bountybench infrastructure
# ---------------------------------------------------------------------------

def _build_and_run_whitebox(
    task: Any,
    run_dir: Path,
    *,
    strix: Path,
    specialist_pack: Path,
    max_turns: int,
    engagement_dir: Path,
    audit_mode: bool,
    common_kwargs: dict[str, Any],
) -> dict[str, Any]:
    if run_dir.exists():
        kind = "audit" if audit_mode else "explore"
        raise BountyBenchError(
            f"{kind} dir already exists: {run_dir} — delete it or resume from a later round"
        )
    plan = build_plan(
        task,
        strix=strix,
        output_dir=run_dir,
        max_turns=max_turns,
        specialist_pack=specialist_pack,
        engagement_dir=engagement_dir,
        audit_mode=audit_mode,
        **common_kwargs,
    )
    write_plan(plan)
    return execute_plan(plan)


# ---------------------------------------------------------------------------
# Target mode: black-box, URL-only, no codebase
# ---------------------------------------------------------------------------

def _build_and_run_target(
    run_dir: Path,
    *,
    target_url: str,
    instructions_file: Path,
    engagement_dir: Path,
    specialist_pack: Path,
    strix: Path,
    max_turns: int,
    audit_mode: bool,
    common_kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Stage workspace, run strix, and collect artifacts for one target run."""
    if run_dir.exists():
        kind = "audit" if audit_mode else "explore"
        raise BountyBenchError(
            f"{kind} dir already exists: {run_dir} — delete it or resume from a later round"
        )

    run_dir.mkdir(parents=True, exist_ok=True)
    staged_engagement = run_dir / "workspace" / "engagement"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Stage engagement dir (master-report, run-additions from H1 templates)
    stage_engagement(
        engagement_dir,
        staged_engagement,
        audit_mode=audit_mode,
        specialist_pack=specialist_pack,
    )

    # Stage instructions.md into run dir and workspace
    staged_instructions = run_dir / "instructions.md"
    shutil.copy2(instructions_file, staged_instructions)
    shutil.copy2(instructions_file, staged_engagement / "instructions.md")

    # Build and write the agent profile
    if audit_mode:
        profile_file = run_dir / "audit-verify-profile.md"
        profile_sources = [specialist_pack / "profiles" / "audit-verify.md"]
    else:
        profile_file = run_dir / "engagement-explorer-profile.md"
        profile_sources = [specialist_pack / "profiles" / "engagement-explore.md"]
    write_audit_profile(profile_file, profile_sources)

    # strix argv — target URL + engagement workspace only, no codebase
    argv: list[str] = [
        str(strix),
        "-n",
        "--target", target_url,
        "--target", str(staged_engagement),
        "--instruction-file", str(staged_instructions),
        "--scan-mode", common_kwargs.get("scan_mode") or "standard",
        "--max-turns", str(max_turns),
    ]

    # strix env
    strix_env: dict[str, str] = {
        "STRIX_TELEMETRY": "0",
        "SCARF_NO_ANALYTICS": "true",
        "DO_NOT_TRACK": "1",
        "OPENAI_AGENTS_DISABLE_TRACING": "1",
        "OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA": "0",
        "STRIX_COMPACT_ROOT_PROMPT_FILE": str(profile_file),
    }
    if v := common_kwargs.get("sandbox_network"):
        strix_env["STRIX_DOCKER_SANDBOX_NETWORK"] = v
        if target_hostname := urlparse(target_url).hostname:
            strix_env["STRIX_SANDBOX_NO_PROXY_EXTRA"] = target_hostname
    if v := common_kwargs.get("sandbox_image"):
        strix_env["STRIX_IMAGE"] = v
    if v := common_kwargs.get("llm"):
        strix_env["STRIX_LLM"] = v
    if v := common_kwargs.get("llm_api_base"):
        strix_env["LLM_API_BASE"] = v
    if v := common_kwargs.get("llm_api_key"):
        strix_env["LLM_API_KEY"] = v
    if v := common_kwargs.get("context_window"):
        strix_env["STRIX_CONTEXT_WINDOW_TOKENS"] = str(v)
    if common_kwargs.get("disable_streaming"):
        strix_env["LLM_DISABLE_STREAMING"] = "1"
    if inject_headers := common_kwargs.get("inject_headers"):
        strix_env["STRIX_INJECT_HEADERS"] = ",".join(inject_headers)
    if block_hosts := common_kwargs.get("block_hosts"):
        strix_env["STRIX_BLOCK_HOSTS"] = ",".join(block_hosts)
    nuclei = Path.home() / "nuclei-templates"
    if nuclei.is_dir():
        strix_env["STRIX_NUCLEI_TEMPLATES_HOST_PATH"] = str(nuclei)
    if v := os.environ.get("TAVILY_API_KEY"):
        strix_env["TAVILY_API_KEY"] = v
    if v := os.environ.get("SEARXNG_URL"):
        strix_env["SEARXNG_URL"] = v

    plan: dict[str, Any] = {
        "adapter": "target-engage",
        "mode": "target",
        "audit_mode": audit_mode,
        "target_url": target_url,
        "engagement_dir": str(engagement_dir),
        "staged_engagement_dir": str(staged_engagement),
        "instruction_file": str(staged_instructions),
        "manifest_file": str(run_dir / "manifest.json"),
        "artifacts_dir": str(artifacts_dir),
        "strix": str(strix),
        "strix_argv": argv,
        "strix_env": strix_env,
        "strix_run_dir_hint": str(run_dir / "strix_runs"),
        "max_turns": max_turns,
        "specialist_pack": str(specialist_pack),
        "status": "planned",
        "created_at": now_iso(),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Execute strix — write output directly to log files so tail -f works during the run
    env = os.environ.copy()
    env.update(strix_env)
    stdout_log = run_dir / "strix.stdout.log"
    stderr_log = run_dir / "strix.stderr.log"
    started = now_iso()
    with open(stdout_log, "w", encoding="utf-8") as out_f, \
         open(stderr_log, "w", encoding="utf-8") as err_f:
        result = subprocess.run(argv, cwd=run_dir, env=env, stdout=out_f, stderr=err_f, check=False)
    completed = now_iso()

    # Make strix_runs readable (written by root-owned container)
    strix_runs_dir = run_dir / "strix_runs"
    if strix_runs_dir.is_dir():
        subprocess.run(["sudo", "chmod", "-R", "a+rX", str(strix_runs_dir)], check=False)

    # rc=1 with "Max turns" in stdout is turn-limit exhaustion, not a hard failure
    stdout_text = stdout_log.read_text(encoding="utf-8", errors="replace")
    soft_exit = result.returncode in {0, 2} or (
        result.returncode == 1 and "Max turns" in stdout_text
    )
    plan.update({
        "status": "completed" if soft_exit else "failed",
        "strix_returncode": result.returncode,
        "started_at": started,
        "completed_at": completed,
    })
    collect_engagement_artifacts(plan)
    (run_dir / "manifest.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return plan


# ---------------------------------------------------------------------------
# Chain loop (mode-agnostic)
# ---------------------------------------------------------------------------

def run_chain(args: argparse.Namespace) -> int:
    mode = args.mode
    engagement_dir = args.engagement.expanduser().resolve()
    strix = args.strix.expanduser()
    notify = not args.no_notify
    max_rounds = args.rounds
    stop_threshold = args.stop_on_dry_runs
    explore_turns = args.explore_turns
    audit_turns = args.audit_turns

    # Resolve specialist pack: explicit arg wins; otherwise use mode default
    if args.specialist_pack is not None:
        specialist_pack = args.specialist_pack.expanduser().resolve()
    elif mode == "target":
        specialist_pack = _TARGET_SPECIALIST_PACK
    else:
        specialist_pack = _DEFAULT_SPECIALIST_PACK

    # Args forwarded unchanged to every build call
    common_kwargs: dict[str, Any] = {
        "scan_mode": args.scan_mode,
        "sandbox_network": args.sandbox_network,
        "sandbox_image": args.sandbox_image,
        "llm": args.llm,
        "llm_api_base": args.llm_api_base,
        "llm_api_key": args.llm_api_key,
        "context_window": args.context_window,
        "disable_streaming": args.disable_streaming,
        "inject_headers": args.inject_headers,
        "block_hosts": args.block_hosts,
    }

    # Mode-specific setup and validation
    auto_start = getattr(args, "auto_start_target", False)
    if mode == "whitebox":
        try:
            task = load_task(args.bountybench, args.project, args.bounty, "detect")
        except BountyBenchError as exc:
            print(f"engage: failed to load task: {exc}", file=sys.stderr)
            return 2

        if auto_start:
            if not _start_target(task.task_dir):
                print("engage: --auto-start-target: failed to start target container", file=sys.stderr)
                return 2

        def run_one(run_dir: Path, *, audit_mode: bool, max_turns: int) -> dict[str, Any]:
            return _build_and_run_whitebox(
                task, run_dir,
                strix=strix, specialist_pack=specialist_pack,
                max_turns=max_turns, engagement_dir=engagement_dir,
                audit_mode=audit_mode, common_kwargs=common_kwargs,
            )

    elif mode == "target":
        instructions_file = args.instructions.expanduser().resolve()
        if not instructions_file.is_file():
            print(
                f"engage: instructions file not found: {instructions_file}\n"
                f"  Copy specialists/bug-bounty-target/templates/instructions.md to that path "
                f"and fill it in before running.",
                file=sys.stderr,
            )
            return 2
        target_url = args.target

        def run_one(run_dir: Path, *, audit_mode: bool, max_turns: int) -> dict[str, Any]:
            return _build_and_run_target(
                run_dir,
                target_url=target_url,
                instructions_file=instructions_file,
                engagement_dir=engagement_dir,
                specialist_pack=specialist_pack,
                strix=strix,
                max_turns=max_turns,
                audit_mode=audit_mode,
                common_kwargs=common_kwargs,
            )
    else:
        print(f"engage: unknown mode {mode!r}", file=sys.stderr)
        return 2

    engagement_dir.mkdir(parents=True, exist_ok=True)

    _log(
        f"chain start — dir={engagement_dir.name}  mode={mode}  "
        f"max_rounds={max_rounds}  stop_on_dry_runs={stop_threshold}  "
        f"explore_turns={explore_turns}  audit_turns={audit_turns}"
    )

    auto_start_task_dir = task.task_dir if (auto_start and mode == "whitebox") else None
    dry_run_streak = 0

    try:
      for round_num in range(1, max_rounds + 1):
        run_n = _next_run_number(engagement_dir)
        run_label = f"run-{run_n:03d}"
        _log(f"=== Round {round_num}/{max_rounds} ({run_label}) ===")

        # ── Explore ──────────────────────────────────────────────────────────
        explore_dir = engagement_dir / f"{run_label}-explore"
        _log(f"explore: {run_label}-explore ({explore_turns} turns max)")
        try:
            explore_result = run_one(explore_dir, audit_mode=False, max_turns=explore_turns)
        except Exception as exc:
            _log(f"explore {run_label} ERROR: {exc}")
            _notify("Engage — chain aborted", f"Explore {run_label} error:\n{exc}", notify)
            return 1

        if explore_result.get("status") != "completed":
            rc = explore_result.get("strix_returncode", "?")
            _log(f"explore {run_label} FAILED (strix_returncode={rc}) — aborting chain")
            _notify("Engage — chain aborted", f"Explore {run_label} failed (rc={rc})", notify)
            return 1

        _log(f"explore {run_label} done")

        # ── Dry-run detection ─────────────────────────────────────────────────
        if _is_dry_run(engagement_dir):
            dry_run_streak += 1
            _log(
                f"dry run — no [pending-audit] items  "
                f"(streak {dry_run_streak}/{stop_threshold})"
            )
            if dry_run_streak >= stop_threshold:
                msg = (
                    f"chain saturated after round {round_num} "
                    f"({dry_run_streak} consecutive dry run(s))"
                )
                _log(msg)
                _notify("Engage — chain saturated", msg, notify)
                return 0
        else:
            if dry_run_streak:
                _log(f"findings present — dry-run streak reset (was {dry_run_streak})")
            dry_run_streak = 0

        # ── Audit ─────────────────────────────────────────────────────────────
        audit_dir = engagement_dir / f"{run_label}-audit"
        _log(f"audit:   {run_label}-audit ({audit_turns} turns max)")
        try:
            audit_result = run_one(audit_dir, audit_mode=True, max_turns=audit_turns)
        except Exception as exc:
            _log(f"audit {run_label} ERROR: {exc}")
            _notify("Engage — chain aborted", f"Audit {run_label} error:\n{exc}", notify)
            return 1

        if audit_result.get("status") != "completed":
            rc = audit_result.get("strix_returncode", "?")
            _log(f"audit {run_label} FAILED (strix_returncode={rc}) — aborting chain")
            _notify("Engage — chain aborted", f"Audit {run_label} failed (rc={rc})", notify)
            return 1

        _log(f"audit {run_label} done")

      msg = (
          f"chain complete — {max_rounds} round(s) finished  "
          f"engagement: {engagement_dir.name}"
      )
      _log(msg)
      _notify("Engage — chain complete", msg, notify)
      return 0
    finally:
      if auto_start_task_dir:
          _stop_target(auto_start_task_dir)


# ---------------------------------------------------------------------------
# Smoke test — one-shot image verification
# ---------------------------------------------------------------------------

def run_smoke(args: argparse.Namespace) -> int:
    """Launch the smoke-test specialist against the sandbox image.

    No engagement dir. Creates a timestamped run dir, runs the smoke-test.md
    profile, parses the resulting smoke-report.md, and exits 0/1.
    """
    strix = args.strix.expanduser()
    specialist_pack = (args.specialist_pack or _SMOKE_SPECIALIST_PACK).expanduser().resolve()
    notify = not args.no_notify

    smoke_profile = specialist_pack / "profiles" / "smoke-test.md"
    if not smoke_profile.is_file():
        print(f"engage smoke: smoke-test.md not found: {smoke_profile}", file=sys.stderr)
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    run_dir = (
        args.output.expanduser().resolve()
        if args.output
        else Path.home() / "wowbagger-runs" / "smoke" / f"smoke-{ts}"
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    workspace_dir = run_dir / "workspace"
    workspace_dir.mkdir(exist_ok=True)
    workspace_dir.chmod(workspace_dir.stat().st_mode | 0o777)

    profile_file = run_dir / "smoke-test-profile.md"
    shutil.copy2(smoke_profile, profile_file)

    instruction_file = run_dir / "instructions.md"
    instruction_file.write_text(
        "# Smoke Test\n\n"
        "Execute the full smoke test procedure defined in your root prompt.\n"
        "Write the final report to `/workspace/smoke-report.md`.\n",
        encoding="utf-8",
    )

    sandbox_image = args.sandbox_image or _SANDBOX_IMAGE_DEFAULT
    strix_env: dict[str, str] = {
        "STRIX_TELEMETRY": "0",
        "SCARF_NO_ANALYTICS": "true",
        "DO_NOT_TRACK": "1",
        "OPENAI_AGENTS_DISABLE_TRACING": "1",
        "OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA": "0",
        "STRIX_COMPACT_ROOT_PROMPT_FILE": str(profile_file),
    }
    if sandbox_image:
        strix_env["STRIX_IMAGE"] = sandbox_image
    if args.sandbox_network:
        strix_env["STRIX_DOCKER_SANDBOX_NETWORK"] = args.sandbox_network
    if args.llm:
        strix_env["STRIX_LLM"] = args.llm
    if args.llm_api_base:
        strix_env["LLM_API_BASE"] = args.llm_api_base
    if args.llm_api_key:
        strix_env["LLM_API_KEY"] = args.llm_api_key
    if args.context_window:
        strix_env["STRIX_CONTEXT_WINDOW_TOKENS"] = str(args.context_window)
    if args.disable_streaming:
        strix_env["LLM_DISABLE_STREAMING"] = "1"

    argv = [
        str(strix),
        "-n",
        "--target", str(workspace_dir),
        "--instruction-file", str(instruction_file),
        "--scan-mode", "standard",
        "--max-turns", str(args.max_turns),
    ]

    _log(
        f"smoke test — image={sandbox_image or '(strix default)'}  "
        f"turns={args.max_turns}  output={run_dir}"
    )

    stdout_log = run_dir / "strix.stdout.log"
    stderr_log = run_dir / "strix.stderr.log"
    env = os.environ.copy()
    env.update(strix_env)
    with open(stdout_log, "w", encoding="utf-8") as out_f, \
         open(stderr_log, "w", encoding="utf-8") as err_f:
        subprocess.run(argv, cwd=run_dir, env=env, stdout=out_f, stderr=err_f, check=False)

    strix_runs_dir = run_dir / "strix_runs"
    if strix_runs_dir.is_dir():
        subprocess.run(["sudo", "chmod", "-R", "a+rX", str(strix_runs_dir)], check=False)

    # Find smoke-report.md anywhere under run_dir
    reports = list(run_dir.rglob("smoke-report.md"))
    if not reports:
        _log("FAIL — smoke-report.md not found (strix may not have completed)")
        _notify("Engage — smoke FAIL", "smoke-report.md not written", notify)
        return 1

    report_path = reports[0]
    report_text = report_path.read_text(encoding="utf-8", errors="replace")

    # Mirror to run_dir root for easy access
    dest = run_dir / "smoke-report.md"
    if report_path != dest:
        shutil.copy2(report_path, dest)

    fail_lines = [l for l in report_text.splitlines() if l.startswith("FAIL")]
    overall_fail = "## Result: FAIL" in report_text or bool(fail_lines)

    if overall_fail:
        _log(f"FAIL — {len(fail_lines)} failure(s):")
        for line in fail_lines[:10]:
            _log(f"  {line}")
        if len(fail_lines) > 10:
            _log(f"  ... ({len(fail_lines) - 10} more — see {dest})")
        _notify("Engage — smoke FAIL", f"{len(fail_lines)} failure(s) — {dest}", notify)
        return 1

    _log(f"PASS — all tools verified  report={dest}")
    _notify("Engage — smoke PASS", f"All tools verified — {dest}", notify)
    return 0


# ---------------------------------------------------------------------------
# Orchestrate — multi-specialist outer loop
# ---------------------------------------------------------------------------

def _load_specialists_json(specialist_pack: Path) -> dict[str, Any]:
    path = specialist_pack / "specialists.json"
    if not path.is_file():
        raise BountyBenchError(
            f"specialists.json not found in specialist pack: {specialist_pack}\n"
            f"  Create {path} — see docs/runbooks/engage-pipeline-plan.md Phase 5."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _load_chain_state(engagement_dir: Path) -> dict[str, Any]:
    path = engagement_dir / "chain-state.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "exhausted": [],
        "current": None,
        "rounds_by_specialist": {},
        "started_at": now_iso(),
        "updated_at": now_iso(),
    }


def _save_chain_state(engagement_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = now_iso()
    (engagement_dir / "chain-state.json").write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8"
    )


def _make_specialist_pack(base_pack: Path, specialist_key: str, entry: dict, tmpdir: Path) -> Path:
    """Create a temp pack with the specialist's profiles as the standard filenames.

    stage_engagement and bountybench.py expect profiles/engagement-explore.md and
    profiles/audit-verify.md — this mapping lets run_chain work without modification.
    """
    pack_dir = tmpdir / specialist_key
    profiles_dir = pack_dir / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(base_pack / entry["explorer"], profiles_dir / "engagement-explore.md")
    shutil.copy2(base_pack / entry["auditor"], profiles_dir / "audit-verify.md")

    templates_src = base_pack / "templates"
    if templates_src.is_dir():
        shutil.copytree(templates_src, pack_dir / "templates")

    return pack_dir


def _build_coordinator_prompt(
    master_report: str,
    manifest: dict,
    available: list[str],
    exhausted: list[str],
) -> str:
    available_lines = "\n".join(
        f"  {key}: {manifest[key]['description']}" for key in available
    )
    exhausted_str = ", ".join(exhausted) if exhausted else "none"
    report_excerpt = master_report[:8000]
    return (
        f"You are a security research coordinator deciding which specialist to run next.\n\n"
        f"Current findings on the target:\n<findings>\n{report_excerpt}\n</findings>\n\n"
        f"Specialists already exhausted (do NOT pick these): {exhausted_str}\n\n"
        f"Available specialists:\n{available_lines}\n\n"
        f"Pick ONE specialist key from the available list that is most likely to find new "
        f"vulnerabilities given the findings above. "
        f"Return ONLY the key (e.g. \"auth\") or \"done\" if no specialist is likely to be "
        f"productive. One word, no explanation, no punctuation."
    )


def _llm_anthropic(model: str, prompt: str, api_key: str) -> str:
    body = json.dumps({
        "model": model,
        "max_tokens": 20,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"]


def _llm_openai_compat(model: str, prompt: str, api_base: str, api_key: str) -> str:
    url = f"{api_base.rstrip('/')}/chat/completions"
    body = json.dumps({
        "model": model,
        "max_tokens": 20,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _coordinator_call(
    master_report: str,
    manifest: dict,
    available: list[str],
    exhausted: list[str],
    args: argparse.Namespace,
) -> str:
    model = getattr(args, "coordinator_llm", None) or args.llm
    if not model:
        raise BountyBenchError(
            "coordinator needs a model: set --llm or --coordinator-llm"
        )
    api_key = args.llm_api_key or os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    api_base = args.llm_api_base or os.environ.get("LLM_API_BASE")

    prompt = _build_coordinator_prompt(master_report, manifest, available, exhausted)
    _log(f"coordinator: calling {model} ({len(available)} specialist(s) available)")

    try:
        if api_base:
            raw = _llm_openai_compat(model, prompt, api_base, api_key or "placeholder")
        elif model.startswith("claude-"):
            if not api_key:
                raise BountyBenchError(
                    "coordinator: set LLM_API_KEY or ANTHROPIC_API_KEY for direct Anthropic calls, "
                    "or set --llm-api-base to route through a proxy"
                )
            raw = _llm_anthropic(model, prompt, api_key)
        else:
            raise BountyBenchError(
                f"coordinator: set --llm-api-base for non-Claude model {model!r}"
            )
    except BountyBenchError:
        raise
    except Exception as exc:
        _log(f"coordinator LLM call failed: {exc} — treating as 'done'")
        return "done"

    key = raw.strip().lower().split()[0].strip(".,;\"'") if raw.strip() else "done"
    if key not in available and key != "done":
        _log(f"coordinator returned unknown key {key!r} (raw: {str(raw)[:80]!r}) — treating as 'done'")
        return "done"
    _log(f"coordinator chose: {key}")
    return key


def run_orchestrate(args: argparse.Namespace) -> int:
    engagement_dir = args.engagement.expanduser().resolve()
    strix = args.strix.expanduser()
    notify = not args.no_notify

    if args.specialist_pack is not None:
        specialist_pack = args.specialist_pack.expanduser().resolve()
    elif args.mode == "target":
        specialist_pack = _TARGET_SPECIALIST_PACK
    else:
        specialist_pack = _DEFAULT_SPECIALIST_PACK

    try:
        manifest = _load_specialists_json(specialist_pack)
    except BountyBenchError as exc:
        print(f"engage: {exc}", file=sys.stderr)
        return 2

    engagement_dir.mkdir(parents=True, exist_ok=True)
    state = _load_chain_state(engagement_dir)

    # Resume: if a specialist was interrupted mid-chain, re-offer it
    if state.get("current") and state["current"] not in state["exhausted"]:
        _log(f"resuming interrupted specialist: {state['current']}")

    _log(
        f"orchestrate start — dir={engagement_dir.name}  mode={args.mode}  "
        f"rounds_per_specialist={args.rounds_per_specialist}  "
        f"already exhausted: {state['exhausted'] or 'none'}"
    )

    with tempfile.TemporaryDirectory(prefix="engage-pack-") as tmpdir:
        tmp = Path(tmpdir)

        while True:
            available = [s for s in manifest if s not in state["exhausted"]]
            if not available:
                msg = f"all specialists exhausted — engagement complete  dir={engagement_dir.name}"
                _log(msg)
                _notify("Engage — orchestration complete", msg, notify)
                return 0

            # First iteration: --start-with overrides coordinator
            start_with = getattr(args, "start_with", None)
            if not state["exhausted"] and start_with:
                if start_with not in manifest:
                    print(f"engage: unknown specialist {start_with!r}", file=sys.stderr)
                    return 2
                next_sp = start_with
                _log(f"using --start-with: {next_sp}")
            else:
                master_path = engagement_dir / "master-report.md"
                master_report = master_path.read_text(encoding="utf-8") if master_path.is_file() else "(no findings yet)"
                try:
                    next_sp = _coordinator_call(master_report, manifest, available, state["exhausted"], args)
                except BountyBenchError as exc:
                    _log(f"coordinator error: {exc} — aborting")
                    _notify("Engage — orchestration aborted", str(exc), notify)
                    return 1

            if next_sp in ("done", "none", ""):
                msg = f"coordinator: no further specialists warranted  dir={engagement_dir.name}"
                _log(msg)
                _notify("Engage — orchestration complete", msg, notify)
                return 0

            _log(f"=== Specialist: {next_sp} ({manifest[next_sp]['description']}) ===")
            state["current"] = next_sp
            _save_chain_state(engagement_dir, state)

            temp_pack = _make_specialist_pack(specialist_pack, next_sp, manifest[next_sp], tmp)

            # Build args namespace for the inner run_chain call
            chain_ns = types.SimpleNamespace(**vars(args))
            chain_ns.specialist_pack = temp_pack
            chain_ns.no_notify = True   # outer loop handles notifications
            chain_ns.rounds = args.rounds_per_specialist

            try:
                rc = run_chain(chain_ns)
            except Exception as exc:
                _log(f"specialist {next_sp} chain ERROR: {exc}")
                _notify("Engage — orchestration aborted", f"Specialist {next_sp} error: {exc}", notify)
                return 1

            if rc != 0:
                _log(f"specialist {next_sp} chain returned rc={rc} — aborting")
                _notify("Engage — orchestration aborted", f"Specialist {next_sp} failed (rc={rc})", notify)
                return rc

            state["exhausted"].append(next_sp)
            state["rounds_by_specialist"][next_sp] = _next_run_number(engagement_dir) - 1
            state["current"] = None
            _save_chain_state(engagement_dir, state)
            _log(f"specialist {next_sp} exhausted — {len(available) - 1} remaining")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _add_run_args(p: argparse.ArgumentParser) -> None:
    # Mode
    p.add_argument(
        "--mode",
        choices=["whitebox", "target"],
        default="whitebox",
        help="whitebox: white-box target with source (BountyBench); target: black-box live URL (H1, CTF, lab)",
    )

    # Chain config
    p.add_argument(
        "--engagement",
        required=True,
        type=Path,
        metavar="CHAIN_DIR",
        help="engagement chain directory (created if absent)",
    )
    p.add_argument(
        "--rounds",
        "--max-rounds",
        type=int,
        default=5,
        metavar="N",
        dest="rounds",
        help="maximum explore+audit rounds to run (default: 5)",
    )
    p.add_argument(
        "--explore-turns",
        type=int,
        default=50,
        metavar="N",
        help="max LLM turns per explore run (default: 50)",
    )
    p.add_argument(
        "--audit-turns",
        type=int,
        default=40,
        metavar="N",
        help="max LLM turns per audit run (default: 40)",
    )
    p.add_argument(
        "--stop-on-dry-runs",
        type=int,
        default=2,
        metavar="N",
        help="stop early after N consecutive explore runs with no new findings (default: 2)",
    )
    p.add_argument(
        "--no-notify",
        action="store_true",
        help="suppress desktop notifications on completion / abort",
    )

    # Target mode args
    tgt = p.add_argument_group("Target mode (--mode target)")
    tgt.add_argument(
        "--target",
        metavar="URL",
        help="target URL (e.g. https://app.example.com)",
    )
    tgt.add_argument(
        "--instructions",
        type=Path,
        metavar="FILE",
        help="path to the per-target instructions.md (required for target mode)",
    )

    # Whitebox mode args
    bb = p.add_argument_group("Whitebox mode (--mode whitebox)")
    bb.add_argument(
        "--auto-start-target",
        action="store_true",
        dest="auto_start_target",
        help="start the BountyBench target container before running and stop it after (docker compose up/down)",
    )
    bb.add_argument(
        "--bountybench",
        type=Path,
        default=_BOUNTYBENCH_DEFAULT,
        metavar="DIR",
        help=f"BountyBench root directory (default: {_BOUNTYBENCH_DEFAULT})",
    )
    bb.add_argument(
        "--project",
        metavar="NAME",
        help="BountyBench project name (required for benchmark mode)",
    )
    bb.add_argument(
        "--bounty",
        type=int,
        default=0,
        metavar="N",
        help="BountyBench bounty index (default: 0)",
    )

    # Strix + model
    p.add_argument(
        "--strix",
        type=Path,
        default=_STRIX_DEFAULT,
        help=f"path to strix binary (default: {_STRIX_DEFAULT})",
    )
    p.add_argument(
        "--specialist-pack",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "specialist pack directory — "
            "defaults to bug-bounty-target for target mode, bug-bounty for whitebox mode"
        ),
    )
    p.add_argument("--llm", metavar="MODEL_ID", default=_LLM_DEFAULT, help="LiteLLM model id override")
    p.add_argument("--llm-api-base", metavar="URL", default=_LLM_API_BASE_DEFAULT, help="LLM API base URL")
    p.add_argument("--llm-api-key", metavar="KEY", default=_LLM_API_KEY_DEFAULT, help="LLM API key or local placeholder")
    p.add_argument(
        "--context-window",
        type=int,
        metavar="TOKENS",
        default=_CONTEXT_WINDOW_DEFAULT,
        help="explicit provider context window token count",
    )
    p.add_argument(
        "--scan-mode",
        default="standard",
        choices=["quick", "standard", "deep"],
        help="strix scan depth (default: standard)",
    )
    p.add_argument("--sandbox-network", metavar="NETWORK", help="Docker network for strix sandbox")
    p.add_argument(
        "--sandbox-image",
        metavar="IMAGE",
        default=None,
        help=(
            "Docker image for strix sandbox "
            f"(default: ENGAGE_SANDBOX_IMAGE env / config sandbox_image"
            + (f" / {_SANDBOX_IMAGE_DEFAULT}" if _SANDBOX_IMAGE_DEFAULT else "") + ")"
        ),
    )
    p.add_argument("--disable-streaming", action="store_true", default=_DISABLE_STREAMING_DEFAULT, help="disable streamed LLM responses")
    p.add_argument(
        "--inject-header",
        metavar="NAME:VALUE",
        action="append",
        dest="inject_headers",
        default=[],
        help="inject a request header into every proxied request (repeatable, e.g. --inject-header 'X-hackerone:the_mop')",
    )
    p.add_argument(
        "--block-host",
        metavar="DOMAIN",
        action="append",
        dest="block_hosts",
        default=[],
        help="null-route a domain inside the sandbox so it is unreachable (repeatable, use for out-of-scope domains)",
    )


def _add_smoke_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="DIR",
        help="directory for this run (default: ~/wowbagger-runs/smoke/smoke-<timestamp>)",
    )
    p.add_argument(
        "--max-turns",
        type=int,
        default=120,
        metavar="N",
        help="max LLM turns for the smoke run (default: 120)",
    )
    p.add_argument("--no-notify", action="store_true", help="suppress desktop notifications")
    p.add_argument(
        "--strix",
        type=Path,
        default=_STRIX_DEFAULT,
        help=f"path to strix binary (default: {_STRIX_DEFAULT})",
    )
    p.add_argument(
        "--specialist-pack",
        type=Path,
        default=None,
        metavar="DIR",
        help="specialist pack containing smoke-test.md (default: multi-specialist pack)",
    )
    p.add_argument("--sandbox-network", metavar="NETWORK", help="Docker network for strix sandbox")
    p.add_argument(
        "--sandbox-image",
        metavar="IMAGE",
        default=None,
        help=(
            "Docker image to smoke-test "
            f"(default: ENGAGE_SANDBOX_IMAGE env / config sandbox_image"
            + (f" / {_SANDBOX_IMAGE_DEFAULT}" if _SANDBOX_IMAGE_DEFAULT else "") + ")"
        ),
    )
    p.add_argument("--llm", metavar="MODEL_ID", default=_LLM_DEFAULT, help="LiteLLM model id")
    p.add_argument("--llm-api-base", metavar="URL", default=_LLM_API_BASE_DEFAULT, help="LLM API base URL")
    p.add_argument("--llm-api-key", metavar="KEY", default=_LLM_API_KEY_DEFAULT, help="LLM API key")
    p.add_argument("--context-window", type=int, metavar="TOKENS", default=_CONTEXT_WINDOW_DEFAULT)
    p.add_argument("--disable-streaming", action="store_true", default=_DISABLE_STREAMING_DEFAULT)


def _add_orchestrate_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the orchestrate subcommand.

    Shares most flags with 'run' (all the strix/model/sandbox flags), but replaces
    --rounds with --rounds-per-specialist and adds coordinator-specific options.
    """
    _add_run_args(p)
    # Replace --rounds semantics for orchestrate
    p.set_defaults(rounds=5)  # fallback if rounds_per_specialist not used directly

    orch = p.add_argument_group("Orchestrate options")
    orch.add_argument(
        "--rounds-per-specialist",
        type=int,
        default=5,
        metavar="N",
        help="max explore+audit rounds per specialist chain (default: 5)",
    )
    orch.add_argument(
        "--start-with",
        metavar="SPECIALIST",
        default=None,
        help="run this specialist first instead of letting the coordinator choose",
    )
    orch.add_argument(
        "--coordinator-llm",
        metavar="MODEL_ID",
        default=None,
        help="model for coordinator calls (default: same as --llm)",
    )


def _add_watch_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "engagement",
        type=Path,
        metavar="ENGAGEMENT_DIR",
        help="engagement directory to watch (the dir passed to --engagement)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="polling interval in seconds (default: 2)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="engage",
        description="Automated multi-round bug bounty chain runner (explore→audit×N)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Single specialist chain (BountyBench):
  engage run --project lunary \\
      --engagement ~/wowbagger-runs/engagements/lunary/chain-002 \\
      --rounds 5 --stop-on-dry-runs 2

  # Full multi-specialist orchestration (BountyBench):
  engage orchestrate --project agentscope \\
      --engagement ~/wowbagger-runs/engagements/agentscope/chain-001 \\
      --rounds-per-specialist 5 --llm anthropic/claude-sonnet-5-5

  # Live target (H1, CTF, lab):
  engage run --mode target --target https://app.example.com \\
      --instructions ~/programs/example/instructions.md \\
      --engagement ~/wowbagger-runs/engagements/example/chain-001
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser(
        "run",
        help="run a single explore→audit chain (one specialist)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_run_args(run_p)
    orch_p = sub.add_parser(
        "orchestrate",
        help="run all specialists sequentially, coordinator-driven",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_orchestrate_args(orch_p)
    smoke_p = sub.add_parser(
        "smoke",
        help="verify every tool in the sandbox image (one-shot, no engagement needed)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_smoke_args(smoke_p)
    watch_p = sub.add_parser(
        "watch",
        help="live terminal dashboard for a running engage orchestrate/run",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_watch_args(watch_p)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        if args.mode == "whitebox" and not args.project:
            parser.error("--project is required for --mode whitebox")
        if args.mode == "target" and not args.target:
            parser.error("--target is required for --mode target")
        if args.mode == "target" and not args.instructions:
            parser.error("--instructions is required for --mode target")
        try:
            return run_chain(args)
        except BountyBenchError as exc:
            print(f"engage: {exc}", file=sys.stderr)
            return 2

    if args.command == "orchestrate":
        if args.mode == "whitebox" and not args.project:
            parser.error("--project is required for --mode whitebox")
        if args.mode == "target" and not args.target:
            parser.error("--target is required for --mode target")
        if args.mode == "target" and not args.instructions:
            parser.error("--instructions is required for --mode target")
        try:
            return run_orchestrate(args)
        except BountyBenchError as exc:
            print(f"engage: {exc}", file=sys.stderr)
            return 2

    if args.command == "smoke":
        try:
            return run_smoke(args)
        except BountyBenchError as exc:
            print(f"engage: {exc}", file=sys.stderr)
            return 2

    if args.command == "watch":
        return run_watch(args)

    parser.error(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
