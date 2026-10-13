# httpx

Purpose: HTTP probing and response fingerprinting.

Runtime note: the wowbagger sandbox wraps ProjectDiscovery tools with `-duc` to disable update checks.

## Syntax

```bash
httpx -u http://target:8000 -title -status-code -tech-detect -follow-redirects
httpx -l urls.txt -status-code -content-length -content-type -location
httpx -u http://target:8000 -path /health,/api,/docs -status-code
```

## Use Rules

- Treat output as triage, not proof.
- Record exact URL, status, and interesting headers.
- Follow up with focused `curl` or browser/proxy requests.
