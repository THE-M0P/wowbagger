# Evidence And Reporting

## Evidence Requirements

Every reported issue needs:

- Exact target and route/function.
- Minimal reproduction.
- Expected vs observed behavior.
- Impact tied to a security boundary.
- Logs, command output, response body, screenshots, or source references.
- Any cleanup performed.

## Avoid

- Scanner-only claims.
- Broad severity claims without exploitability.
- Hidden benchmark metadata in detect-mode reports.
- Irreproducible payloads.
- Multiple unrelated issues in one finding.

## Confidence Levels

- Confirmed: exploit or proof demonstrates impact.
- Likely: strong source evidence but proof blocked by environment.
- Ruled out: tested and behavior prevents exploitation.
- Needs follow-up: promising but missing decisive evidence.
