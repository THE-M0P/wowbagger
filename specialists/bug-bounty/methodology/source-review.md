# Source Review

## Fast Triage

Start with framework-specific entry points:

- Python: `routes`, `views`, `api`, `urls.py`, `main.py`, `app.py`, decorators, middleware.
- Node: `routes`, `controllers`, `server`, `app`, `middleware`, `package.json` scripts.
- Go: `cmd`, `internal`, HTTP handlers, router setup, config loaders.
- Java: controllers, filters, serializers, XML/YAML/parser usage.

## Sink Classes

- Command execution.
- SQL/query builders.
- Template rendering.
- File path construction.
- Deserialization.
- SSRF-capable HTTP clients.
- Redirects and URL parsing.
- Auth decisions and object lookup.
- Cryptographic verification.

## Review Pattern

For each source-to-sink path, write:

```text
source -> parser -> validation -> authorization -> sink -> observable impact
```

If a link is unknown, inspect or test it before concluding.
