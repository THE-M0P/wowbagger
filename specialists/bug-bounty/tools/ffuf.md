# ffuf

Purpose: content discovery and parameter fuzzing.

## Syntax

```bash
ffuf -u http://target:8000/FUZZ -w words.txt -mc all -fc 404
ffuf -u http://target:8000/api/FUZZ -w api-words.txt -mc 200,204,301,302,401,403,500
ffuf -u http://target:8000/search?q=FUZZ -w params.txt -fs 0
```

## Use Rules

- Establish a baseline 404 and error response first.
- Filter by status, size, and words carefully.
- Avoid destructive payloads unless explicitly in scope.
