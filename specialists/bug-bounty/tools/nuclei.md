# nuclei

Purpose: template-based vulnerability checks.

Runtime note: the wowbagger sandbox wraps ProjectDiscovery tools with `-duc` to disable update checks.

## Syntax

```bash
nuclei -u http://target:8000 -severity low,medium,high,critical
nuclei -l urls.txt -tags cve,exposure,misconfig
nuclei -u http://target:8000 -jsonl -o nuclei.jsonl
```

## Use Rules

- Do not report from Nuclei output alone.
- Confirm with a minimal request and source/root-cause evidence.
- Keep template output as supporting evidence only.
