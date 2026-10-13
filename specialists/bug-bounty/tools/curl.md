# curl

Purpose: minimal HTTP proofs.

## Syntax

```bash
curl -i http://target:8000/
curl -i -X POST http://target:8000/submit/ -d 'username=test'
curl -i -H 'Content-Type: application/json' -d '{"username":"test"}' http://target:8000/submit_json/
curl -sS -D headers.txt -o body.txt http://target:8000/path
```

## Use Rules

- Prefer `curl -i` or `-D` so headers are captured.
- Keep payloads minimal.
- Save exact commands used for evidence.
