# Bug Bounty Specialist Pack

Purpose: give the agent durable, versioned operating knowledge for authorized bug bounty and benchmark work.

This pack is designed for evidence-first web and source-assisted vulnerability research. It borrows structure from BountyBench's detect/exploit/patch lifecycle, Project Naptime's hypothesis-driven workflow, EnIGMA/SWE-agent's emphasis on reliable interactive tools, PentestGPT's context management split, and Cybench-style evaluation records.

## Structure

- `AGENTS.md`: behavior contract for a bug bounty specialist.
- `profiles/`: compact active profiles for specific runtimes and benchmark modes.
- `methodology/`: durable testing method, organized by workflow.
- `tools/`: command syntax and usage rules for common tools.
- `playbooks/`: benchmark and engagement execution flows.
- `adapters/`: output contracts for benchmark scoring versus real engagements.
- `templates/`: reusable note, evidence, and finding formats.
- `references.md`: research sources that shaped the pack.

## Default Active Profile

For BountyBench detect mode with local Qwen, start with:

```text
profiles/bountybench-detect-compact.md
playbooks/bountybench-detect.md
playbooks/route-handler-review.md
adapters/bountybench.md
templates/surface-coverage.md
```

Keep broad methodology and tool syntax files available as references, but load them only when the current surface needs them.

## Engagement Pipeline (multi-session chains)

For extended BountyBench research using the explorer/auditor loop (via `engage run --mode whitebox`), the adapter auto-selects profiles — do not pass them manually:

- **Explorer**: `profiles/engagement-explore.md` — auto-loaded when `--engagement` is passed without `--audit`
- **Auditor**: `profiles/audit-verify.md` — auto-loaded when `--engagement --audit` are both passed

The engagement pipeline maintains a persistent `master-report.md` across runs. See `evals/README.md` for the full architecture and launch commands.

For live black-box targets (H1, CTF, lab VM), use the `bug-bounty-target/` pack instead (auto-selected by `engage run --mode target`).

## Operating Principle

Do not treat scanners as the result. The specialist should repeatedly:

1. Map the target and source.
2. Form a concrete vulnerability hypothesis.
3. Test it with the smallest reproducible action.
4. Record request, response, command, output, and source references.
5. Apply `methodology/impact-gates.md`.
6. Decide whether evidence supports, weakens, or rejects the hypothesis.

Use `adapters/bountybench.md` only for BountyBench-style scoring where a runnable exploit artifact is required. Use `adapters/real-engagement.md` for real bug bounty reporting.
