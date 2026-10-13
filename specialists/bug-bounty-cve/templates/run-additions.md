# Run Additions — run-<N>-explore

<!-- Written by the explorer at the end of every engagement run.
     Placed at /workspace/engagement/run-additions.md inside the sandbox,
     then mirrored to <chain-dir>/run-N-explore/run-additions.md by the adapter.
     The auditor reads this once and merges it into master-report.md.
     Do not write directly to master-report.md from an explorer run. -->

Date: YYYY-MM-DD
Explorer turns used: (set by adapter)
Context pressure: N%
Scope confirmed: yes / partial (note any out-of-scope surfaces encountered)

---

## New Findings (pending audit)

<!-- One entry per finding. The auditor will verify each before promoting to master-report.
     Be precise — the auditor replays these steps exactly against the live target.
     If no new findings: write "(none this session)" -->

### [pending-audit] Finding Title Here

- **Route:** METHOD /path
- **Attacker capability:** <who the attacker is — account type, role, what they start with>
- **Security boundary crossed:** <what auth/ownership check was missing or bypassed>
- **Demonstrated impact:** <what the attacker gained — data read, state change, privilege, etc.>
- **Proof steps:**
  1. <exact curl command — include all headers, body, and expected response>
  2. <exact curl command>
  3. <expected response showing impact, e.g. 200 with marker data>
- **Negative control:** <what shows this is not normal behaviour — e.g. sibling route with same ID returns 403, unknown ID returns 404>
- **HTTP evidence:** <describe the response differential that proves the boundary was crossed — without source references>
- **Test accounts used:** <which of your created accounts were used — A, B, viewer, etc.>
- **Confidence:** high / medium / low
- **Remaining uncertainty:** <anything the auditor should double-check>
- **Suggested severity:** Critical / High / Medium / Low
- **Suggested CVSS:** CVSS 3.1 vector string if known

---

## New Ruled-Out Surfaces

<!-- One line per surface. Include the specific HTTP evidence that ruled it out.
     If none: write "(none this session)" -->

- `METHOD /path` — <reason: e.g. "returns 403 for cross-org caller; confirmed via HTTP — same route scoped correctly">

---

## New Anomalies

<!-- Observed behaviour that is suspicious but not yet confirmed as a finding.
     The auditor will attempt minimal reproduction.
     If none: write "(none this session)" -->

### [pending-audit] Anomaly Title Here

- **Observed:** <what happened — response code, body excerpt, timing, error>
- **Tried:** <what was tested to investigate it>
- **Needed to confirm:** <what next step would confirm or rule it out>
- **Reproduction command:** <minimal curl to reproduce the observation>

---

## Contradictions

<!-- Use if any observation contradicts a verified finding in master-report.md.
     If none: write "(none this session)" -->

### [contradiction: finding-N] <title of existing finding>

- **Existing finding:** <brief description>
- **New evidence:** <what was observed that contradicts it>
- **Suggested action:** downgrade to anomaly / re-verify / no change needed

---

## Out-of-Scope Surfaces Encountered

<!-- Surfaces that appeared interesting but fell outside program scope.
     Record so future sessions don't re-investigate them.
     If none: write "(none this session)" -->

- `METHOD /path` — [out-of-scope] <reason: domain not in scope / explicitly excluded>

---

## Surface Coverage This Session

<!-- Compact table of what was tested. One row per route or surface cluster. -->

| Surface | Method(s) | Scope | Tested | Outcome |
|---------|-----------|-------|--------|---------|
| /api/v1/... | GET | in-scope | yes | ruled-out |

---

## Notes for Next Session

<!-- Warm leads, open questions, or context the next explorer should know.
     Keep it brief — the master report carries the full history.
     The auditor will convert actionable hypotheses into Leads in master-report.md. -->
