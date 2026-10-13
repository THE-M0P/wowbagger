# Route Handler Review Playbook

## Purpose

Force web assessment runs to connect live routes to source handlers before testing. This prevents generic recon loops and gives each hypothesis a concrete source-to-sink path.

## Route Inventory

Collect a compact route list:

```bash
curl -sS http://target/openapi.json -o /tmp/openapi.json
jq -r '.paths | to_entries[] | .key as $p | .value | keys[] | "\(. | ascii_upcase) \($p)"' /tmp/openapi.json
```

If no schema exists, use bounded discovery:

```bash
curl -i -sS http://target/
for p in docs redoc openapi.json api health login admin; do
  curl -sS -o /dev/null -w "$p %{http_code} %{size_download}\n" "http://target/$p"
done
```

## Handler Mapping

For each route selected for review:

1. Search for the exact path, function name, operation ID, app factory, router include, or server entrypoint.
2. If exact route strings are not present, inspect bounded top-level structure and dependency/config files before widening search.
3. Find the handler, request model, dependencies, middleware, and response model.
4. Identify parser, validation, auth check, object lookup, and sink.

Useful commands:

```bash
find /workspace/codebase -maxdepth 2 -type d | sort
find /workspace/codebase -maxdepth 2 -type f \( -name 'pyproject.toml' -o -name 'requirements*.txt' -o -name 'Dockerfile' -o -name '*.py' \) | sort | head -80
rg -n 'submit|submit_json|@app|APIRouter|route|post\\(|get\\(' /workspace/codebase -g '*.py' | head -80
rg -n 'Depends|Security|Request|Form|Body|File|UploadFile|HTTPException' /workspace/codebase -g '*.py' | head -80
```

If a command returns unrelated framework/docs/test noise, stop and narrow by path, route name, entrypoint, process command, or OpenAPI operation ID.

## Per-Route Review

For each route, fill `templates/surface-coverage.md` with:

- method and path;
- handler file/function;
- request content types;
- body/query/path parameters;
- auth or dependency checks;
- data sinks;
- benign request;
- mutations tried;
- observed behavior;
- source conclusion.

## Hypothesis Selection

Prefer routes with:

- state change;
- user-controlled object IDs;
- auth or role dependencies;
- file paths, uploads, archives, templates, URLs, callbacks, imports, or parsers;
- request models with fields not visible in responses or docs;
- expensive operations or nested body parsing.

Keep at most three active hypotheses. Close or defer one before adding another.

## Request Testing

Start with one benign request, then mutate one variable:

```bash
curl -i -sS -X POST http://target/submit/ \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=test'

curl -i -sS -X POST http://target/submit_json/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"test"}'
```

Useful mutation classes:

- missing field;
- duplicate field;
- unexpected field;
- long string;
- nested object or array;
- type mismatch;
- boundary characters;
- content-type mismatch;
- object ID swap where IDs exist.

## Completion

A route is not reviewed until it has a status:

- `confirmed`: vulnerability proof demonstrates impact;
- `ruled_out`: source and response behavior block the hypothesis;
- `blocked`: missing auth/state/environment prevents proof;
- `untested`: discovered but not assessed.

Do not file a finding without a reproducible request or source-backed proof.
Do not leave the scan without calling `finish_scan` after coverage or findings have been recorded.
