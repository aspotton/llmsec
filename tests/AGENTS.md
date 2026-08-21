# Test-suite instructions for coding agents

This subtree verifies both ordinary correctness and security behavior.

Rules:

- Every bug fix should add a regression test.
- New detectors need positive, benign-negative, and malformed/adversarial cases where applicable.
- Security-sensitive behavior changes must add or update `tests/security/` coverage.
- Keep `tests/security/` fast enough to run on every push and pull request.
- Do not weaken expectations merely to make a change pass; update behavior and documentation intentionally.
- Large adaptive or model-evaluation suites belong under `evals/`, not the fast unit-test suite.
- Adversarial Unicode is intentional in this project, but Python test source should normally encode security-relevant confusables, full-width forms, zero-width characters, bidi controls, tags, and variation selectors with explicit Unicode escapes or code-point construction.
- Do not globally disable Ruff ambiguous-Unicode rules for fixtures. If a literal code point is truly required, use the narrowest suppression possible and document why.

Read:

- `docs/development/testing.md`
- `docs/development/ci.md`
- `docs/security/threat-model.md`
- `docs/development/unicode-fixtures.md`
