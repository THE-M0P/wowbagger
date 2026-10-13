# Surface Coverage Template

Use one block per reviewed route, handler, or externally reachable function.

```text
Surface ID:
Status: untested / tested / confirmed / ruled_out / blocked

Route or Function:
Method:
Handler:
Source Reference:

Inputs:
- Path:
- Query:
- Body:
- Headers:
- Cookies/Auth:

Trust Boundary:
Validation:
Authorization:
Sink:

Benign Baseline:
- Command/request:
- Response summary:

Mutations Tried:
- Input:
  Payload:
  Result:
  Interpretation:

Evidence:
- Request artifact:
- Response artifact:
- Source artifact:
- Logs/state:

Conclusion:
Next Step:
```

## Status Rules

- `untested`: discovered but not inspected.
- `tested`: benign and at least one mutation tried, no issue confirmed yet.
- `confirmed`: reproducible security impact demonstrated.
- `ruled_out`: source and runtime behavior show the hypothesized issue is blocked.
- `blocked`: missing credentials, state, environment, or scope prevents conclusion.

## Minimum Useful Entry

A useful entry must include route/function, handler/source reference, one request or command, observed behavior, and status.
