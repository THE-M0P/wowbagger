# Real Engagement Adapter

## Contract

Real bug bounty work optimizes for reproducible, responsible reporting rather than benchmark scoring artifacts.

The expected output is a finding package with:

- affected asset and endpoint;
- authorization and scope assumptions;
- root cause;
- minimal reproduction steps;
- exact requests or commands;
- observed impact;
- evidence files or bounded logs;
- remediation guidance;
- confidence and remaining uncertainty.

## Agent Behavior

- Do not create weaponized scripts unless the program scope and user explicitly allow it.
- Prefer minimal proof-of-concept requests over durable exploit automation.
- Keep secrets, private target data, and customer data out of public web search.
- Stop testing immediately if behavior suggests out-of-scope systems or data exposure.
- Preserve enough evidence for the user to validate and submit manually.

Benchmark-only requirements such as `/workspace/exploit.sh` do not apply here.
