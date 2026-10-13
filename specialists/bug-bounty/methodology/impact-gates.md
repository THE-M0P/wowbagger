# Impact Gates And False-Positive Control

Use this before writing any vulnerability finding, exploit artifact, or final report. The goal is to make the agent a better security tester, not a better benchmark guesser.

## Finding Gate

A reportable issue must answer all of these:

- Affected asset: the exact route, handler, parameter, file, or workflow.
- Attacker capability: what an unauthenticated or lower-privileged user can control.
- Trust boundary: what authorization, parser, storage, network, filesystem, or availability boundary is crossed.
- Measurable impact: data exposure, unauthorized state change, command/file/network access, sustained availability harm, or another concrete security outcome.
- Minimal proof: the smallest request or command that reproduces the behavior.
- Counterevidence: what normal or defensive behavior was observed and why it does not rule the issue out.

If any item is missing, record the surface as `needs follow-up` or `ruled out` instead of reporting a finding.

## Runtime-Enforced Gate

The agent's dynamic vulnerability report tool requires four explicit impact-gate fields:

- `attacker_capability`: what the attacker can do before exploitation.
- `security_boundary`: the auth, tenant, user, role, server resource, filesystem, network, database, process, or equivalent boundary crossed or exhausted.
- `demonstrated_impact`: the unauthorized result directly shown by the proof.
- `negative_controls`: the benign baseline or counter-test that rules out normal behavior.

The runtime rejects broad parent CWEs such as `CWE-20`, `CWE-74`, `CWE-77`, `CWE-200`, `CWE-284`, and `CWE-693` for confirmed dynamic reports. Use a precise child CWE or omit the CWE until the mechanism is clear.

For availability findings, the report must include measured sustained degradation, resource exhaustion, crash, timeout, worker/process impact, or failed health-check evidence. A single slow request or failed probe is not enough — the attack must be active while impact is measured on concurrent or subsequent requests, not inferred from the attack request's own response time.

## Common Non-Findings

Do not report these by themselves:

- A normal `400`, `401`, `403`, `404`, or validation error.
- A stack trace, framework error shape, or verbose message with no sensitive data or exploit path.
- Duplicate request fields where the application deterministically picks one value and no authorization or integrity boundary is crossed.
- Extra JSON fields that are ignored or rejected.
- Different formatting between JSON, form, or text responses without security impact.
- Parser or content-type inconsistencies that only produce normal validation behavior.
- One transient `500` response without repeatability, root cause, or user-visible impact.
- Scanner output that has not been reduced to a minimal proof.

## Availability Gate

Availability testing must be bounded, reversible, and measured.

Before calling something denial of service or resource exhaustion, collect:

- Baseline latency, status code, and response body shape.
- A small controlled mutation or concurrency increase.
- Evidence of sustained impact: latency increase, worker starvation, CPU/memory pressure, failed health checks, or repeated errors.
- Recovery behavior after stopping the probe.
- A source explanation tying attacker-controlled input to expensive work or missing limits.

Start with low request counts, short timeouts, and small payloads. Stop if impact is clear or if the target shows no sustained degradation.

## Pivot Rule

After two low-signal probes on the same hypothesis, choose one:

- reduce the test to a smaller proof;
- map a different source sink for the same route;
- mark the hypothesis `ruled out` or `needs follow-up`;
- move to a new route and bug class.

Do not keep reading generic framework internals or rerunning equivalent requests after source and runtime behavior already explain the result.

## Generalization Rule

Benchmark adapters may specify artifact paths or scoring mechanics. They must not teach hidden answers, target-specific exploit classes, or benchmark-only shortcuts. Keep reusable hunting rules in methodology and keep benchmark contracts in adapters.
