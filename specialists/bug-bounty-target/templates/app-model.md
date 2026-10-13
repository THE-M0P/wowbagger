# App Model — <program>

<!-- Explorer-owned. Written at end of Step 3, updated each session.
     Read by: explorer (Step 1 — before doing anything), auditor (replay context).
     Never written by the auditor.
     Replace <program> with the engagement directory name. -->

Last updated: never
Updated by: (run name)

---

## Authentication

- **Mechanism:** (JWT / session cookie / API key / other)
- **If JWT — algorithm:** (RS256 / HS256 / none / other — from jwt_tool output)
- **Token location:** (Authorization: Bearer / Cookie name)
- **Cookie flags:** (Secure: yes/no · HttpOnly: yes/no · SameSite: strict/lax/none/not set)
- **Observed token lifetime:** (e.g. 24h · 7d · no expiry observed)
- **Refresh mechanism:** (refresh token endpoint / re-login required / none observed)

## Identity & Roles

- **ID format:** (UUID / integer / slug / mixed — note which resources use which)
- **Roles observed:** (e.g. admin · owner · member · viewer · guest)
- **Multi-tenancy model:** (e.g. org → team → user · flat / single-tenant · none observed)
- **Account creation:** (open registration / invite-only / admin-only / email verification required)

## Resource Model

<!-- What objects the application manages and who can do what to them.
     Fill one row per resource type. Leave cells blank if not yet tested. -->

| Resource | Owner | Create | Read | Update | Delete | ID type |
|----------|-------|--------|------|--------|--------|---------|
| (fill in) | | | | | | |

## SSRF Surface

- **Webhook URL fields:** (yes — routes: LIST · no · not observed)
- **Avatar / logo URL input:** (yes — routes: LIST · no · not observed)
- **URL import / preview:** (yes — routes: LIST · no · not observed)
- **OAuth redirect parameters:** (yes — routes: LIST · no · not observed)
- **Other URL-accepting features:** (describe or "none observed")

## Rate Limiting

- **Observed limits:** (e.g. 429 after ~30 req/min on /api/* · none observed)
- **Retry-after behaviour:** (Retry-After header value if seen · not observed)

## Tech Signals

- **Framework / server hints:** (from Server header · error pages · stack traces · "none")
- **Database hints:** (from error messages · query fragments in responses · "none")
- **Interesting headers:** (e.g. X-Powered-By: Express · X-Request-Id format · CORS policy)

---

## Surface Map

<!-- Discovery log only — list every route found, grouped by function.
     Never remove entries. Never annotate investigation status here.

     Investigation status lives exclusively in master-report.md:
       Confirmed Findings / Ruled Out / Anomalies / Leads
     Cross-reference both files to find unexplored routes:
       routes in this Surface Map not mentioned anywhere in master-report.md = unexplored. -->

### Auth / session
(none yet)

### User / account
(none yet)

### Admin / elevated privilege
(none yet)

### Resources / data
(none yet)

### Webhooks / integrations / external URL features
(none yet)

### Other / unknown
(none yet)
