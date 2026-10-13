# Master Report — <chain-name>

<!-- One master report per chain. The auditor owns writes to this file.
     The explorer reads it but writes only to run-additions.md.
     Replace <chain-name> with the chain directory name. -->

Last audited: never
Target: <URL>
Chain started: YYYY-MM-DD

---

## Confirmed Findings

<!-- Items promoted from [pending-audit] by the auditor.
     Format: [verified: audit-N] title — one-line summary, then details. -->

(none yet)

<!--
Example entry:

### [verified: audit-1] Broken object-level authorization on GET /v1/runs/{id}/feedback

- **Route:** GET /v1/runs/{id}/feedback
- **Attacker:** Unauthenticated network client who knows a run UUID
- **Boundary crossed:** Project membership / org boundary
- **Impact:** Anonymous caller reads project owner's private feedback (free-text comment, rating, score)
- **Proof steps:**
  1. Authenticate as owner: `POST /auth/login` → JWT
  2. Write marker: `PATCH /v1/runs/{id}/feedback?projectId={pid}` -d '{"comment":"MARKER"}' → 200
  3. Read unauthenticated: `GET /v1/runs/{id}/feedback` (no headers) → 200 with marker
- **Negative control:** `GET /v1/runs/{unknown-id}/feedback` → 404
- **Source:** `packages/backend/src/api/v1/runs/index.ts:1141` — no project/org predicate; `auth/utils.ts:89` — publicRoutes allowlist
- **Artifact:** run-001-explore/artifacts/exploit.sh (exits 0)
- **Submitted to HackerOne:** no
-->

---

## Ruled Out

<!-- One line per surface. Written by auditor after verifying the ruling.
     Format: [ruled-out] surface — reason -->

(none yet)

<!--
Example entries:

- [ruled-out] GET /v1/runs/{id} — scoped by orgId at line 849, cross-org access returns 401
- [ruled-out] JWT secret brute-force — secret is 64+ random bytes, not guessable
- [ruled-out] Mass assignment on POST /v1/projects — extra fields ignored, no state change
-->

---

## Anomalies

<!-- Observed but unconfirmed. Auditor sets status after each pass.
     [anomaly-active]  = still worth pursuing
     [anomaly-stale]   = 3+ consecutive sessions failed to confirm; deprioritised -->

(none yet)

<!--
Example entry:

### [anomaly-active] 500 error on d.format column in datasets endpoint

- **Observed:** GET /v1/datasets?projectId=X returns 500 "column d.format does not exist"
- **Tried:** run-001 — basic schema mismatch probe; run-002 — tried injecting via format param
- **Needed to confirm:** whether format param is user-controlled and reaches a dangerous sink
- **Source ref:** packages/backend/src/api/v1/datasets/index.ts:~120
- **Session count:** 2 sessions, still active
-->

---

## Leads

<!-- Specific hypotheses left by previous sessions, not yet confirmed or ruled out.
     Populated by the auditor from the explorer's "Notes for Next Session".
     The next explorer should check these before forming new candidates.
     Remove a lead when it has been investigated (finding, anomaly, or ruled-out). -->

(none)

<!--
Example entries:

- [lead] PATCH /v1/runs/:id/feedback (cross-org write) — handler reads existingFeedback by run ID only, no project predicate; check whether user B can overwrite user A's feedback (confirm: PATCH with B's token to A's run UUID, then GET feedback to see if marker persists)
- [lead] Private-API-key branch sweep — authMiddleware skips ?projectId membership check on API-key paths; grep for other ctx.request.query.projectId usages on non-public routes beyond the one already confirmed
-->

---

## Session History

| Run | Date | Exp turns | Aud turns | New confirmed | New anomalies | Notes |
|-----|------|-----------|-----------|---------------|---------------|-------|
| — | — | — | — | — | — | chain started |

---

## Status Marker Reference

| Marker | Set by | Meaning |
|--------|--------|---------|
| `[pending-audit]` | Explorer via additions.md | Unverified claim awaiting auditor |
| `[verified: audit-N]` | Auditor | Confirmed reproducible in audit pass N |
| `[ruled-out]` | Auditor | Tested, not a finding |
| `[anomaly-active]` | Auditor | Observed, unconfirmed, still worth pursuing |
| `[anomaly-stale]` | Auditor | 3+ sessions failed to confirm; deprioritised |
| `[contradiction: finding-N]` | Explorer via additions.md | New evidence contradicts a verified finding |
