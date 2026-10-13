# Semgrep

Purpose: source-code pattern search and lightweight static analysis.

Sandbox runtime: `SEMGREP_SEND_METRICS=off` and `SEMGREP_ENABLE_VERSION_CHECK=0` are set. Do not use `--config auto` or `--config p/...` — these require a metrics-enabled network call to semgrep.dev and will fail. Use inline patterns or local rule files only.

## Syntax

```bash
# Inline pattern search (preferred — no network needed)
semgrep -e 'subprocess.$FUNC(shell=True)' --lang python .
semgrep -e 'eval(...)' --lang python .
semgrep -e 'exec(...)' --lang python .
semgrep -e 'os.system(...)' --lang python .

# JSON output for piping
semgrep -e 'pattern' --lang python --json --output semgrep.json .

# Multiple patterns via local rule file
semgrep --config /path/to/rules.yaml .
```

## Use Rules

- Use Semgrep to find source paths and sinks.
- Confirm findings with dataflow, request proof, or a minimal test.
- Keep Semgrep JSON as supporting evidence, not the conclusion.
