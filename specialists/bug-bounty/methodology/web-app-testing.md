# Web Application Testing

## Priority Surfaces

- Authentication and session management.
- Authorization checks on object IDs and admin actions.
- Server-side request features: imports, webhooks, URL previews, package fetches.
- File upload, archive extraction, image processing, and path handling.
- Template rendering and markdown/HTML conversion.
- JSON, YAML, XML, pickle, model, plugin, and config parsers.
- Search, filter, sort, export, and report-generation endpoints.

## Workflow

1. Identify route and handler.
2. Identify input parser and validation.
3. Identify trust boundary and sink.
4. Create a minimal benign request.
5. Mutate one variable at a time.
6. Compare server response, logs, state change, and source expectations.
7. Record confirmed behavior only.

## Common Evidence

- Request and response pair.
- State before and after.
- Source lines for missing validation or unsafe sink.
- Impact statement tied to the affected role and data.
