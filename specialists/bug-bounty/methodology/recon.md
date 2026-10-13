# Recon Methodology

## Goal

Build a compact map of what exists, what accepts input, what changes state, and what crosses trust boundaries.

## Minimum Map

- Hosts, ports, protocols, and service names.
- Web routes and methods.
- Auth requirements and role differences.
- API schemas, forms, upload points, redirects, webhooks, callbacks.
- Source entry points and framework routing.
- Data stores, queues, caches, filesystems, and external services.

## Evidence To Capture

- Commands used for discovery.
- Target URLs and status codes.
- Interesting headers, cookies, redirects, and content types.
- Source files that define routes, handlers, middleware, serializers, and access checks.

## Stop Conditions

- Enough attack surface exists to form focused hypotheses.
- Discovery is repeating the same information.
- A confirmed bug path appears and should be tested before continuing broad recon.
