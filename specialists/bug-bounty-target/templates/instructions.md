# Program Instructions — <program name>

<!-- Fill this in before the first run against a new program.
     Staged into /workspace/engagement/instructions.md by the adapter.
     Both explorer and auditor read this file.
     Keep it up to date — test accounts added by the explorer should be recorded here. -->

Program: <name>
Target: <primary URL, e.g. https://app.example.com>
H1 Program URL: <https://hackerone.com/program-name>
Last updated: YYYY-MM-DD

---

## Scope (IN SCOPE — test these)

<!-- List domains, subdomains, and paths that are explicitly in scope.
     The explorer must check every surface against this list before testing. -->

- https://app.example.com (primary target)
- https://api.example.com
- *.example.com (wildcard if applicable)

---

## Out of Scope (HARD STOP — do not test)

<!-- The explorer must not test anything on this list, even if it looks interesting. -->

- Third-party integrations (Stripe, Twilio, SendGrid, etc.)
- *.example-cdn.com / static assets
- The program's own HackerOne program page
- Social engineering or phishing
- Physical security
- Denial of service attacks

---

## Test Accounts

<!-- Populated on first run if the explorer creates accounts.
     Updated in place — append new accounts as they are created.
     Format: Role | Email | Password | Notes -->

<!-- Created by explorer during run-001-explore: -->
| Role | Email | Password | Notes |
|------|-------|----------|-------|
| (none yet — explorer will create on first run) | | | |

---

## Program Notes

<!-- Rate limits, known restrictions, triage preferences, deadlines. -->

- Rate limit: <e.g. "known 429 at >10 req/s; stay under 2 req/s">
- Account creation: <allowed / restricted / requires email verification>
- Duplicate policy: <e.g. "active program, check for similar public reports">
- Disclosure timeline: <e.g. "90-day coordinated">
- Triage preference: <e.g. "prefers CVSS over subjective labels; requires working PoC">
- Additional notes: <anything else the agent should know>

---

## Known Architecture

<!-- Populated as the chain progresses. Explorer adds surface discoveries here.
     Keeps future sessions from re-discovering the same basics. -->

- Auth: <e.g. "Bearer JWT in Authorization header; refresh via POST /auth/refresh">
- Multi-tenancy: <e.g. "org-based; projectId scopes resources">
- API versioning: <e.g. "/api/v1/; v2 exists but is undocumented">
- Object ID format: <e.g. "UUID v4 throughout">
- Roles observed: <e.g. "owner, admin, member, viewer">
