# Security limitations

V0.1 is a scaffold and useful local inspection runtime, not a complete LLM security boundary.

Important limitations:

- the prompt-injection detector is heuristic, not a trained semantic model;
- Unicode coverage is intentionally incomplete;
- encoded-content inspection is currently limited to bounded printable Base64 candidates;
- there is no first-class tool/action reference monitor yet;
- there is no provenance/authority or data-lineage engine yet;
- long-context fragmentation is not solved;
- there is no streaming holdback or token-level scanning;
- the default policy is intentionally simple;
- no classifier can be assumed robust against an adaptive attacker merely because it performs well on a fixed benchmark.

Applications should not interpret `DecisionAction.ALLOW` as proof that content is safe. It means the configured V0.1 checks did not trigger a blocking rule.
