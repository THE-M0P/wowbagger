# Telemetry

Telemetry is disabled in the DeepThought fork.

The runtime keeps no-op compatibility shims for upstream call sites, but those
shims do not open network connections, persist identifiers, or send analytics
events.
