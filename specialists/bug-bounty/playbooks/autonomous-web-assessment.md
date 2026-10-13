# Autonomous Web Assessment Playbook

## Phases

1. Scope confirmation.
2. Surface mapping.
3. Source-assisted route review.
4. Hypothesis queue.
5. Focused testing.
6. Evidence consolidation.
7. Report writing.

## Hypothesis Queue Format

```text
ID:
Surface:
Bug class:
Why plausible:
Proof needed:
Risk if true:
Status:
```

Keep no more than five active hypotheses. Finish or discard one before adding more.

## Tool Discipline

- Use broad scanners to suggest hypotheses.
- Use focused requests and source review to confirm them.
- Use interactive browser/proxy tooling when auth or state matters.
- Use Semgrep for source-path leads, not final proof by itself.
