# Master Report — <chain-name>

<!-- One master report per chain. The auditor owns writes to this file.
     The explorer reads it but writes only to run-additions.md.
     Replace <chain-name> with the engagement directory name. -->

Last audited: never
Program: <program name>
Target: <URL>
H1 Program: <hackerone.com/program-name>
Chain started: YYYY-MM-DD

---

## Confirmed Findings

<!-- Items promoted from [pending-audit] by the auditor.
     Every field is required before submission to H1. -->

(none yet)

<!--
Example entry:

### [verified: audit-1] Cross-tenant IDOR — GET /api/v1/projects/{id}/members returns any project's members

- **Route:** GET /api/v1/projects/{id}/members
- **Severity:** Medium (CVSS 3.1: 6.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **OWASP:** BOLA / A01 Broken Access Control
- **Attacker:** Authenticated user (any role) with a valid session token in the application
- **Boundary crossed:** Project membership boundary — the route accepts any project UUID in the path and returns member data without verifying the caller belongs to that project
- **Impact:** Read-only exposure of member list (names, emails, roles) for any project in the application. Attacker does not need to know the target project's name — UUIDs can be discovered via their own projects' URLs.
- **Proof steps (replayed YYYY-MM-DD, all reproduced):**
  1. Account A creates project P_A: `POST /api/v1/projects` (JWT_A) → `{"id":"aaa-111", ...}`
  2. Account B (separate org, confirmed no membership in P_A): `GET /api/v1/projects/aaa-111/members` (JWT_B) → `200 [{"email":"user_a@test.com","role":"owner"}]`
  3. Confirm boundary is real: `GET /api/v1/projects/aaa-111` (JWT_B) → `403 Forbidden` (B cannot view the project itself)
- **Negative control:** `GET /api/v1/projects/00000000-0000-0000-0000-000000000000/members` (JWT_B) → `404` (unknown ID rejected; route is a real predicate)
- **HTTP evidence:** Route accepts attacker-controlled `{id}` path param and returns 200 with member data belonging to a project the attacker has no membership in. Sibling `GET /projects/{id}` returns 403 for the same caller, confirming the membership check exists elsewhere but is missing on this sub-resource.
- **Remediation:** Verify the caller's membership in project `{id}` before returning the member list. The same check applied to `GET /projects/{id}` should be applied uniformly to all sub-resources under that project.
- **Submitted to H1:** no
-->

---

## Ruled Out

<!-- One line per surface. Written by auditor after verifying the ruling. -->

(none yet)

<!--
Example entries:
- [ruled-out] GET /api/v1/projects/{id} — returns 403 for non-member caller; membership check confirmed via HTTP (sibling member-list route is the finding)
- [ruled-out] POST /api/v1/invites — org-scoped; invitation token validates against the caller's org at redemption time
-->

---

## Anomalies

<!-- Observed but unconfirmed. Auditor sets status after each pass.
     [anomaly-active]  = still worth pursuing
     [anomaly-stale]   = 3+ consecutive sessions failed to confirm; deprioritised -->

(none yet)

<!--
Example entry:

### [anomaly-active] POST /api/v1/billing/upgrade reachable by viewer role (missing BFLA check)

- **Observed:** Viewer account receives no 403 when POSTing to the upgrade route; request hangs waiting on Stripe rather than being rejected at the auth layer.
- **Tried:** run-002 — source-confirmed no role check. run-003 — live viewer account confirmed no 403 vs. 403 on the control route.
- **Needed to confirm:** Demonstrate the viewer can complete the upgrade flow (Stripe is not fully wired in the test environment).
- **Reproduction command:** `curl -sS -X POST https://app.example.com/api/v1/billing/upgrade -H "Authorization: Bearer $JWT_VIEWER" -d '{"plan":"team"}'`
- **Session count:** 2
-->

---

## Leads

<!-- Specific hypotheses from prior sessions, not yet confirmed or ruled out.
     Populated by the auditor from the explorer's "Notes for Next Session".
     The next explorer should check these before forming new candidates.
     Remove a lead when it has been investigated (finding, anomaly, or ruled-out). -->

(none)

<!--
Example entries:
- [lead] GET /api/v1/reports/{id}/export — export sub-resource may not verify project membership; test: Account B fetches export for Account A's report UUID (confirm: 200 with A's data; rule out: 403 or 404)
- [lead] PATCH /api/v1/users/{id} — `role` field included in update schema; test: viewer sends role=owner in own update (confirm: role changes; rule out: field ignored or 422)
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
