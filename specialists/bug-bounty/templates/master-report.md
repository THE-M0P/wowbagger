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

### [verified: audit-1] Broken object-level authorization on GET /api/items/{id}/notes

- **Route:** GET /api/items/{id}/notes
- **Attacker:** Authenticated user with no relationship to the target item
- **Boundary crossed:** Item ownership / visibility boundary
- **Impact:** Authenticated attacker reads notes attached to another user's private item
- **Proof steps:**
  1. Authenticate as owner (Account A): `POST /auth/login` → JWT
  2. Create item with private note: `POST /api/items` body '{"visibility":"private","note":"MARKER"}' → item ID
  3. Read notes as unrelated user (Account B): `GET /api/items/{id}/notes` with Account B token → 200 with "MARKER"
- **Negative control:** `GET /api/items/{unknown-id}/notes` → 404
- **Source:** `src/api/items/handler.js:87` — ownership check applied to item route but not notes sub-route
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

- [ruled-out] GET /api/items/{id} — scoped by ownerId predicate, cross-owner access returns 403
- [ruled-out] JWT secret brute-force — secret is 64+ random bytes, not guessable
- [ruled-out] Mass assignment on POST /api/users — extra fields stripped by schema validator, no state change
-->

---

## Anomalies

<!-- Observed but unconfirmed. Auditor sets status after each pass.
     [anomaly-active]  = still worth pursuing
     [anomaly-stale]   = 3+ consecutive sessions failed to confirm; deprioritised -->

(none yet)

<!--
Example entry:

### [anomaly-active] 500 error on sort parameter in search endpoint

- **Observed:** GET /api/search?q=test&sort=invalid returns 500 "invalid sort column"
- **Tried:** run-001 — basic schema mismatch probe; run-002 — tried injecting via sort param
- **Needed to confirm:** whether sort param is user-controlled and reaches a dangerous SQL sink
- **Source ref:** src/api/search/handler.js:~80
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

- [lead] PATCH /api/items/:id/notes (cross-owner write) — handler looks up note by ID only, no owner predicate; check whether Account B can overwrite Account A's note (confirm: PATCH with B's token to A's note ID, then GET note to see if marker persists)
- [lead] API-key auth bypass sweep — middleware skips ownership check on API-key paths; grep for other query param ownership checks applied inconsistently across public vs authenticated routes
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
