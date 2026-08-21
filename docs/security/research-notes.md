# Research notes and architectural implications

This document records research that motivated the architecture. It is not a benchmark claim for the current implementation.

## Character-level/adaptive guardrail attacks

- *LLM Guardrails: A Comprehensive Analysis of Detection and Mitigation Techniques against LLM Attacks* / related adversarial guardrail research: https://arxiv.org/abs/2504.11168
- Design implication: canonicalization and raw-character signals must be first-class, and evaluation must include attacks adapted to the released defense rather than only fixed public examples.

## LLM Guard

- Archived Protect AI project: https://github.com/protectai/llm-guard
- Design implication: preserve the approachable scanner ergonomics and local operation, but avoid sequential text mutation and make findings/policy separate concepts.

## Guardrails AI

- Project: https://github.com/guardrails-ai/guardrails
- Design implication: single-purpose validators/detectors are a useful extension model, but the core runtime should remain independent of remote services or a hosted hub.

## Role confusion

- *Prompt Injection as Role Confusion*: https://arxiv.org/abs/2603.12277
- Design implication: host-known provenance and authority must remain authoritative outside natural-language context. Future detectors should explicitly model role impersonation/fake authorization rather than assuming prompt-injection vocabulary is sufficient.

## Instruction/data separation

- ASIDE research: https://arxiv.org/abs/2503.10566
- Design implication: a future project-trained detector should fuse trusted metadata through a separate feature path rather than relying only on text tags such as `[TRUST=UNTRUSTED]`.

## Agent security and deterministic enforcement

- CaMeL: https://arxiv.org/abs/2503.18813
- AgentDojo: https://arxiv.org/abs/2406.13352
- Design implication: detection should not be the final action boundary. Future tool security should enforce capabilities, effects, schemas, destinations, approvals, and source-influence rules outside the LLM.

## Long-context fragmentation

Long-context attacks can distribute malicious intent across windows that appear harmless independently. The project roadmap therefore calls for global window aggregation and suspicious-fragment reconstruction rather than only maximum-score chunking.

## Project stance

No research result is treated as proof that prompt injection can be completely solved by a classifier. The framework is intentionally layered so improved detection can coexist with deterministic enforcement as the project matures.
