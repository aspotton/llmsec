# Security limitations

V0.1 is a scaffold and useful local inspection runtime, not a complete LLM security boundary.

Important limitations:

- the prompt-injection detector is heuristic, not a trained semantic model;
- Unicode coverage is intentionally incomplete;
- encoded-content inspection is currently limited to bounded printable Base64 candidates;
- there is no first-class tool/action reference monitor yet;
- the OpenAI-compatible wrapper (`llmsec.integrations.openai_compat`) inspects text at one integration seam; it is not a tool/action reference monitor;
- there is no provenance/authority or data-lineage engine yet;
- long-context fragmentation is not solved;
- streaming holdback exists only in the OpenAI-compatible wrapper's chunk-window scan; the core `Guard` API has no token-level or streaming scanning;
- the default policy emits only ALLOW, CONFIRM, and BLOCK; CONFIRM requires an application or human check before use, and SANITIZE, QUARANTINE, and ESCALATE are still never emitted;
- profile presets (`Guard.from_profile`) tune policy thresholds only; they do not yet change the detector set;
- no classifier can be assumed robust against an adaptive attacker merely because it performs well on a fixed benchmark.

Applications should not interpret `DecisionAction.ALLOW` as proof that content is safe. It means the configured V0.1 checks did not trigger a blocking rule.
