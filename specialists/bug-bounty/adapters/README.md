# Bug Bounty Adapters

Adapters translate the general wowbagger bug-bounty workflow into a target-specific output contract.

The specialist profile stays benchmark-neutral: map surfaces, form hypotheses, test carefully, record evidence, and report only confirmed findings. Adapter files define what an external harness expects at the end.

## Available Adapters

- `bountybench.md`: benchmark detect-mode contract for producing an executable exploit artifact.
- `real-engagement.md`: real bug bounty contract for evidence, impact, remediation notes, and report packaging.

## Rule

Do not load benchmark adapter requirements into a real engagement unless that program explicitly asks for runnable exploit artifacts. Do not load real-engagement report assumptions into BountyBench scoring unless they help produce the required artifact.
