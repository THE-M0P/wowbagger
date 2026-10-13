from __future__ import annotations

import argparse
import json
from pathlib import Path

from wowbagger_evals.config import SPECIALIST_PACK as _DEFAULT_SPECIALIST_PACK
from wowbagger_evals.bountybench import (
    BountyBenchError,
    build_plan,
    execute_plan,
    load_task,
    write_plan,
)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        task = load_task(args.bountybench, args.project, args.bounty, args.mode)
        plan = build_plan(
            task,
            strix=args.strix,
            output_dir=args.output,
            scan_mode=args.scan_mode,
            max_turns=args.max_turns,
            sandbox_network=args.sandbox_network,
            sandbox_image=args.sandbox_image,
            llm=args.llm,
            llm_api_base=args.llm_api_base,
            llm_api_key=args.llm_api_key,
            reasoning_effort=args.reasoning_effort,
            context_window=args.context_window,
            min_finish_turns=args.min_finish_turns,
            disable_streaming=args.disable_streaming,
            replay_chat_history=args.replay_chat_history,
            compact_bug_bounty_profile=args.compact_bug_bounty_profile,
            specialist_pack=args.specialist_pack or _DEFAULT_SPECIALIST_PACK,
            engagement_dir=args.engagement,
            audit_mode=args.audit,
        )
        write_plan(plan)
        if args.command == "run":
            if not args.allow_execute:
                parser.error("run requires --allow-execute")
            plan = execute_plan(plan)
    except BountyBenchError as exc:
        parser.exit(2, f"wowbagger-eval: {exc}\n")

    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wowbagger-eval",
        description="wowbagger evaluation adapters",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_common(subparsers.add_parser("plan", help="write a sanitized run plan"))
    run_parser = subparsers.add_parser("run", help="execute a sanitized run plan")
    add_common(run_parser)
    run_parser.add_argument(
        "--allow-execute",
        action="store_true",
        help="execute the generated Strix command",
    )
    return parser


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bountybench", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--bounty", required=True, type=int)
    parser.add_argument("--mode", default="detect", choices=["detect"])
    parser.add_argument("--strix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--scan-mode",
        default="standard",
        choices=["quick", "standard", "deep"],
    )
    parser.add_argument("--max-turns", default=120, type=int)
    parser.add_argument(
        "--sandbox-network",
        help="Docker network name for the wowbagger sandbox container",
    )
    parser.add_argument(
        "--sandbox-image",
        help="Docker image name for the wowbagger sandbox container",
    )
    parser.add_argument(
        "--llm",
        help="LiteLLM model id to use for the benchmark run",
    )
    parser.add_argument(
        "--llm-api-base",
        help="LLM API base URL for local model providers",
    )
    parser.add_argument(
        "--llm-api-key",
        help="LLM API key or local-provider placeholder",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh", "max"],
        help="value for STRIX_REASONING_EFFORT in the benchmark child process",
    )
    parser.add_argument(
        "--context-window",
        type=int,
        help="explicit provider context window for audit and compaction",
    )
    parser.add_argument(
        "--min-finish-turns",
        type=int,
        help="block finish_scan until this LLM turn to collect long-run behavior",
    )
    parser.add_argument(
        "--disable-streaming",
        action="store_true",
        help="disable streamed LLM responses for providers that reject agent histories while streaming",
    )
    parser.add_argument(
        "--replay-chat-history",
        action="store_true",
        help="replay prior chat context for local chat backends that reject tool-only continuations",
    )
    parser.add_argument(
        "--compact-bug-bounty-profile",
        action="store_true",
        help="use the compact bug-bounty profile as the agent's root prompt",
    )
    parser.add_argument(
        "--specialist-pack",
        default=None,  # resolved from config.py / ENGAGE_SPECIALIST_PACK env var
        type=Path,
        help="path to the bug-bounty specialist pack used by --compact-bug-bounty-profile",
    )
    parser.add_argument(
        "--engagement",
        default=None,
        type=Path,
        metavar="CHAIN_DIR",
        help="path to the engagement chain directory (enables multi-session pipeline mode)",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="run as auditor (verifies pending-audit items in run-additions.md, updates master-report.md)",
    )


if __name__ == "__main__":
    raise SystemExit(main())
