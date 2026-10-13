# Run Additions — run-<N>-explore

<!-- Written by the explorer at the end of every engagement run.
     Placed at /workspace/engagement/run-additions.md inside the sandbox,
     then mirrored to <chain-dir>/run-N-explore/run-additions.md by the adapter.
     The auditor reads this once and merges it into master-report.md.
     Do not write directly to master-report.md from an explorer run. -->

Date: YYYY-MM-DD
Explorer turns used: (set by adapter)
Context pressure: N%

---

## New Findings (pending audit)

<!-- One entry per finding. The auditor will verify each before promoting to master-report.
     Be precise — the auditor replays these steps exactly.
     If no new findings: write "(none this session)" -->

### [pending-audit] Finding Title Here

- **Route:** METHOD /path
- **Attacker capability:** <who the attacker is and what access they start with>
- **Security boundary crossed:** <what auth/ownership check was missing or bypassed>
- **Demonstrated impact:** <what the attacker gained — data read, state change, etc.>
- **Proof steps:**
  1. <exact curl command or action>
  2. <exact curl command or action>
  3. <expected response showing impact>
- **Negative control:** <what shows this is not normal behavior — e.g. sibling route with same ID returns 401>
- **Source reference:** `<file>:<line>` — <what the code shows>
- **Artifact:** `run-<N>-explore/artifacts/exploit.sh` — bash -n passed, proof run exits 0
- **Confidence:** high / medium / low
- **Remaining uncertainty:** <anything the auditor should double-check>

---

## New Ruled-Out Surfaces

<!-- One line per surface. Include the specific evidence that ruled it out.
     If none: write "(none this session)" -->

- `METHOD /path` — <reason: e.g. "orgId scoped at line 849, cross-org returns 401">

---

## New Anomalies

<!-- Observed behavior that is suspicious but not yet confirmed as a finding.
     The auditor will attempt minimal reproduction and set [anomaly-active] or downgrade.
     If none: write "(none this session)" -->

### [pending-audit] Anomaly Title Here

- **Observed:** <what happened — response code, body, timing, error>
- **Tried:** <what was tested to investigate it>
- **Needed to confirm:** <what next step would confirm or rule it out>
- **Source reference:** `<file>:<line>` (if found)
- **Reproduction command:** <minimal curl or command to reproduce the observation>

---

## Contradictions

<!-- Use this section if any observation this session contradicts a verified finding
     in master-report.md. Rare but important — e.g. a patched endpoint.
     If none: write "(none this session)" -->

### [contradiction: finding-N] <title of existing finding>

- **Existing finding:** <brief description of what was verified>
- **New evidence:** <what was observed that contradicts it>
- **Suggested action:** downgrade to anomaly / re-verify / no change needed

---

## Surface Coverage This Session

<!-- Compact table of what was tested. One row per route or surface cluster. -->

| Surface | Method(s) | Tested | Outcome |
|---------|-----------|--------|---------|
| /v1/... | GET | yes | ruled-out |

---

## Notes for Next Session

<!-- Optional. Warm leads, open questions, or context the next explorer should
     know before starting. Keep it brief — the master report carries the full history. -->
