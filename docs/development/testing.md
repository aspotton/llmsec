# Testing

The test hierarchy separates ordinary correctness from security regressions.

```text
tests/unit/         small behavior tests
tests/integration/  public API and composition tests
tests/security/     fast known-attack regressions
```

Run locally:

```bash
pytest
pytest -m security
```

Every bug fix should add a regression test. New detectors should include positive cases and benign negatives. Security-sensitive changes should demonstrate the old failure mode where practical.

Larger adaptive/model evaluations belong under `evals/` so every commit does not require an expensive benchmark run.


## Adversarial Unicode fixtures

Unicode security tests are expected to exercise confusable, full-width, zero-width, bidirectional, tag, combining, and variation-selector characters. In Python source, represent security-relevant or visually ambiguous characters with explicit Unicode escapes or code-point construction rather than pasting the literal glyph. This keeps diffs auditable and preserves Ruff's ambiguous-Unicode checks as a useful safeguard.

See [`unicode-fixtures.md`](unicode-fixtures.md) for the project-wide convention, including the narrow exception for fixtures that must preserve exact literal bytes/code points.
