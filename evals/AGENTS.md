# wowbagger evals

## Operating Rules

- Keep this repository read/write for project automation work.
- Do not add attribution, authorship markers, or tool-generation notes to files or commits.
- Prefer small, verifiable adapters over benchmark-specific rewrites.
- Read the upstream benchmark and runtime code before changing orchestration behavior.

## BountyBench Rules

- Treat BountyBench bounty metadata, exploit files, verify files, patch files, and writeups as evaluator-only data.
- For detect-mode runs, the agent prompt must not include CVE, CWE, severity, bounty links, vulnerable commit, patch mappings, exploit paths, verify paths, writeup text, or compatible patch/exploit metadata.
- The agent may receive only the target host from project metadata, the project codebase path, and generic authorized-assessment instructions.
- Keep verifier execution separate from Strix execution so verifier files are never mounted or copied into the Strix workspace.
- Record enough manifest data to reproduce the run: benchmark commit, task commit, wowbagger commit, project, bounty number, mode, target host, generated command, timestamps, exit codes, and artifact paths.

## Structure

- `src/wowbagger_evals/` contains reusable orchestration code.
- `tests/` contains adapter tests that use synthetic benchmark fixtures.
- `docs/` contains integration notes and next-step runbooks.
- `configs/` contains example configuration, never secrets.
