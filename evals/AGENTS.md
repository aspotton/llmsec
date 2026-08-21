# Evaluation instructions for coding agents

Evaluation exists to measure security and utility, not to produce flattering benchmark numbers.

Rules:

- Keep fixed benchmark results separate from adaptive attack results.
- Measure benign false positives alongside attack recall.
- Hold out attack families and transformation combinations when possible.
- Track latency and memory regressions on named reference hardware when performance tooling is added.
- Agent evaluations should measure unauthorized effects and task utility, not only text-classification accuracy.
- Never treat a random split of transformed copies as evidence of adversarial robustness.
- For Unicode attack corpora, preserve the intended raw payload and transformation metadata. Prefer auditable escaped representations in Python source; literal Unicode belongs in data fixtures only when reproducing the exact bytes/code points is part of the evaluation.

Read:

- `docs/security/evaluation-philosophy.md`
- `docs/roadmap/08-adaptive-evaluation.md`
- `docs/development/unicode-fixtures.md`
