---
name: caido
description: Caido proxy — reading captured traffic, replaying requests, and querying request history when live execution is blocked (CDN failures, CSP, anti-bot).
---

# Caido Proxy

All sandbox HTTP traffic routes through the Caido proxy automatically via the `HTTP_PROXY` / `HTTPS_PROXY` environment variables. Every request made by `curl`, `httpx`, `requests`, or agent-browser is captured and searchable — no extra setup needed.

## Tools

### `list_requests`

Query captured traffic with HTTPQL filters.

```
list_requests(
    httpql_filter="req.path.cont:\"/api/\"",
    first=50,
    sort_by="timestamp",      # timestamp | host | method | path | status_code | response_time | response_size | source
    sort_order="desc",        # asc | desc
    scope_id=None,
)
```

Returns `{ entries: [...], page_info: { has_next_page, end_cursor, ... } }`.

**Pagination:** Only pass `after` when you have a real `end_cursor` from a previous call's `page_info`. Never pass `"None"`, `"null"`, `"0"`, or `""` — those are rejected. Omit the parameter entirely for the first call or when not paginating.

Each entry includes: `cursor`, `request.id`, `request.host`, `request.method`, `request.path`, `request.query`, `request.is_tls`, `request.created_at`, and a `response` object with `id`, `status_code`, `length`, `created_at`.

### `view_request`

Get the raw bytes of a captured request or its response.

```
view_request(
    request_id="<id from list_requests>",
    part="request",           # "request" | "response"
    search_pattern=None,      # optional regex for compact hit view
    page=1,
    page_size=50,
)
```

Without `search_pattern`: returns paginated raw content + `has_more`.  
With `search_pattern`: returns up to 20 regex matches with 40-char before/after context — useful for finding reflected input, leaked credentials, or hidden parameters.

### `repeat_request`

Replay a captured request with optional field overrides.

```
repeat_request(
    request_id="<id>",
    modifications={
        "url": "https://...",                # replace full URL
        "params": {"key": "new_val"},        # add/update query params
        "headers": {"X-Custom": "value"},    # add/update headers
        "body": '{"id": 99}',               # replace body entirely
        "cookies": {"session": "abc..."},    # add/update cookies
    },
)
```

Inherits everything from the original (auth, headers, method) and overlays only the specified fields. The standard BOLA/IDOR test loop is: browse → capture → `list_requests` → `repeat_request` with a modified `id`, `user_id`, or `Authorization`.

### `list_sitemap` / `view_sitemap_entry`

Caido builds a request-tree (sitemap) from observed traffic.

```
list_sitemap(scope_id=None, parent_id=None, depth="DIRECT", page=1)
view_sitemap_entry(entry_id="<id>")
```

Omit `parent_id` for root-level domains. Pass an entry id with `depth="DIRECT"` for immediate children or `"ALL"` to drill fully. `view_sitemap_entry` returns the entry plus its 30 most recent related requests — fast way to see what Caido has for a path without filtering.

### `scope_rules`

Filter which traffic the tools see.

```
scope_rules(action="create", scope_name="semrush-only", allowlist=["*.semrush.com"], denylist=["*.gif","*.png","*.css","*.js","*.ico","*.woff*"])
scope_rules(action="list")
scope_rules(action="delete", scope_id="<id>")
```

Actions: `list`, `get`, `create`, `update`, `delete`. An empty allowlist = allow all. Denylist always wins. Pass `scope_id` to `list_requests` to restrict results to a single scope.

## HTTPQL Filter Syntax

```
# Integer fields: resp.code, req.port, id, roundtrip
resp.code.eq:200
resp.code.gte:400
req.port.eq:443

# Text fields: req.method, req.host, req.path, req.query, req.ext, req.raw
req.method.eq:"POST"
req.path.cont:"/api/user"
req.host.regex:".*\\.semrush\\.com"

# Date fields
req.created_at.gt:"2024-01-01T00:00:00Z"

# Logical operators
req.method.eq:"POST" AND resp.code.gte:400
req.host.eq:"www.semrush.com" OR req.host.eq:"api.semrush.com"

# Negation — NO NOT operator; use negated forms:
req.path.ncont:"/static"   # not contains
req.ext.ne:"js"            # not equal

# Bare string: full-text search across req.raw + resp.raw
"api_key" OR "access_token"
```

**Quoting rule:** Strings require quotes; integers do not. `resp.code.eq:200` is correct; `resp.code.eq:"200"` is a parse error.

## CDN Fallback Pattern

When a third-party script fails to load inside the sandbox (CDN blocks container IPs, CSP, anti-bot), query Caido's captured history for values the browser already computed **before** the sandbox was launched.

```
# Browser loaded FingerprintJS and fired POST /sso/user-sessions/activate
# The sandbox CDN request fails → don't re-execute the script
# Instead:
list_requests(httpql_filter='req.path.cont:"user-sessions/activate"')
# → find the request ID
view_request(request_id="<id>", part="request")
# → read the Custom-User-Hash header value from the raw bytes
```

This works for any computed header or token that was generated on a real browser visit and passed through the proxy: FingerprintJS `visitorId`, Amplitude device IDs, device fingerprint tokens, CSRF tokens, etc. The proxy's history is the ground truth; the script execution is redundant.

## Python Access (`caido_api` module)

From sandbox Python scripts (via `exec_command`), import `caido_api` directly — it connects to the same running Caido instance:

```python
import asyncio
from caido_api import list_requests, view_request, repeat_request

async def main():
    conn = await list_requests(
        httpql_filter='req.method.eq:"POST" AND req.host.eq:"www.semrush.com"',
        first=100,
    )
    for edge in conn.edges:
        req = edge.node.request
        body = await view_request(req.id, part="request")
        raw = body.request.raw.decode("utf-8", errors="replace")
        if "Custom-User-Hash" in raw:
            print(req.id, raw[:500])

asyncio.run(main())
```

Available: `list_requests`, `view_request`, `repeat_request`, `list_sitemap`, `view_sitemap_entry`, `scope_rules`.

**Pagination from Python:** `conn.edges` is the list; `conn.page_info.has_next_page` and `conn.page_info.end_cursor` drive the next call. Pass `end_cursor` as `after=` — only when it's a real value.

## Common Patterns

**Find all POST requests to a target:**
```
list_requests(httpql_filter='req.method.eq:"POST" AND req.host.eq:"www.semrush.com"', first=100)
```

**Find requests containing a specific token:**
```
list_requests(httpql_filter='"sm2.user.api_key"')
```

**Inspect a specific path:**
```
list_requests(httpql_filter='req.path.cont:"/dpa/insights"')
```

**Test BOLA — cross-account id swap:**
```
# 1. list_requests to find the original
# 2. view_request to confirm the object ID
# 3. repeat_request with modifications={"body": '{"id": <victim_id>}'}
```

**Sweep for leaked credentials in all responses:**
```
list_requests(httpql_filter='"api_key" OR "access_token" OR "secret"')
```
