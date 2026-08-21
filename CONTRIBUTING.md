# Contributing to llmsec

Thank you for your interest in contributing to llmsec.

llmsec is a security-focused project, so contributions should prioritize correctness, clarity, reproducibility, low-latency behavior, and avoiding changes that silently weaken security guarantees.

## Before You Start

Please read the repository-level `AGENTS.md` and any more specific `AGENTS.md` files in the directory you plan to modify.

For larger changes, also review the relevant documentation under `docs/`, especially:

- `docs/architecture/` for architectural principles and execution design
- `docs/security/` for threat-model and security considerations
- `docs/development/` for testing and contributor conventions
- `docs/roadmap/` for planned future work

If a change affects a documented architectural principle, security boundary, public API, or roadmap item, update the relevant documentation as part of the same pull request.

## Licensing of Contributions

llmsec is licensed under the Apache License, Version 2.0.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project is provided under the terms of the Apache License, Version 2.0, consistent with Section 5 of that license.

By opening a pull request or otherwise submitting code, documentation, tests, or other material for inclusion in this repository, you represent that you have the right to submit that contribution under those terms.

Do not submit code copied from another project unless its license is compatible with Apache-2.0 and all required copyright, attribution, and notice obligations are preserved.

If your contribution incorporates third-party code, data, models, or other licensed material, call that out clearly in the pull request.

## Development Setup

llmsec requires Python 3.11 or newer.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Upgrade packaging tools and install the project with development dependencies:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[dev]'
```

## Required Checks

Before opening a pull request, run:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
```

GitHub Actions runs automated checks on pushes and pull requests. A contribution should not weaken, bypass, or disable CI checks merely to make a change pass.

### Tests

Behavioral changes should include tests.

Bug fixes should include a regression test whenever practical.

New detectors should include, where applicable:

- positive malicious/adversarial cases
- benign negative cases
- edge cases and malformed input
- false-positive-sensitive examples
- security regression cases for known bypass techniques

Security-sensitive changes should include tests that demonstrate both the protection being added and legitimate behavior that must continue to work.

## Security Regression Tests

Security regressions are different from ordinary correctness regressions.

A code change may be functionally correct while accidentally making a detector less robust against prompt injection, encoding tricks, Unicode obfuscation, or other adversarial inputs.

When changing security-sensitive behavior, consider whether the change belongs in the security regression suite.

Do not update expected results solely because a security test began failing. First determine whether the failure represents a real regression.

## Unicode and Adversarial Text Fixtures

This project intentionally tests visually ambiguous, invisible, and adversarial Unicode.

When a Unicode code point is security-relevant because of its exact identity, invisibility, or visual ambiguity, prefer explicit escapes in Python source rather than pasting the literal character directly.

For example:

```python
full_width = "\uFF21\uFF22\uFF23"
zero_width_space = "\u200B"
bidi_override = "\u202E"
```

This keeps security fixtures auditable and allows Ruff's ambiguous-Unicode checks to remain enabled.

Literal Unicode may still be appropriate in external fixture files when preserving the exact raw payload is itself part of the test. If a linter suppression is genuinely required, use the narrowest possible suppression and explain why.

See `docs/development/unicode-fixtures.md` for the canonical project guidance.

## Code Style

Keep the public API small, typed, and predictable.

In particular:

- prefer typed enums and value objects over free-form security strings
- detectors produce findings; policy produces decisions
- detectors should not mutate shared source content
- reuse shared content views rather than repeating normalization or parsing
- keep expensive operations bounded
- keep production dependencies separate from training-only dependencies
- preserve local-first and low-latency operation
- avoid introducing network calls into the default inspection path
- do not treat model-generated language as an authorization boundary

Follow existing naming, typing, and module conventions unless the change intentionally revises them.

## Dependencies

Avoid adding runtime dependencies unless they provide clear value that cannot reasonably be achieved with the existing stack.

A new dependency should be:

- actively maintained
- appropriately licensed
- reasonably small for its purpose
- justified in the pull request
- evaluated for supply-chain and security implications

Training, evaluation, and development dependencies should not become required production dependencies unless there is a compelling reason.

## Public API Changes

Changes to public interfaces should preserve backward compatibility when practical.

If a breaking change is necessary:

1. explain why it is needed
2. update examples and documentation
3. add or update tests
4. update the changelog when appropriate

Security-related concepts should use strongly typed representations rather than accepting arbitrary strings internally.

## Performance

Latency is a first-class project goal.

Changes to hot-path code should avoid unnecessary:

- repeated normalization
- repeated tokenization
- sequential execution of independent checks
- allocations
- model loads
- network calls

If a change materially affects runtime performance, include benchmark results or enough information for reviewers to reproduce them.

## Models, Training, and Evaluation

Before modifying training or evaluation code, read the applicable `AGENTS.md` files under `training/` and `evals/`.

Training changes should preserve:

- dataset provenance
- license metadata
- reproducible configurations
- train/evaluation separation
- transformation history for adversarial examples
- resistance to data poisoning and unreviewed production feedback

Evaluation changes should avoid optimizing only for static benchmark accuracy. False positives, held-out attack families, adaptive attacks, and latency are all relevant.

## Documentation

User-facing behavior should be documented.

Use:

- `README.md` for a concise human-oriented introduction and quick start
- `docs/` for detailed architecture, guides, security rationale, and roadmap
- `AGENTS.md` for concise instructions to coding agents and pointers to authoritative documentation

Avoid duplicating large sections of documentation into `AGENTS.md`.

## Pull Requests

Keep pull requests focused when practical.

A good pull request should explain:

- what changed
- why it changed
- any security implications
- tests added or updated
- performance impact, if relevant
- new dependencies or third-party material, if any

Small, reviewable changes are generally easier to validate safely than large unrelated bundles.

## Reporting Security Vulnerabilities

Do not open a public issue for a vulnerability that could enable practical bypasses, unauthorized actions, sensitive-data exposure, or other security impact.

Follow the private reporting instructions in `SECURITY.md`.

Public issues are appropriate for non-sensitive bugs, feature requests, documentation improvements, and already-disclosed security research.

## Questions and Proposals

For small fixes, a pull request is usually enough.

For substantial architectural changes, new security primitives, major dependencies, or changes to threat-model assumptions, open a discussion or issue first when practical so the direction can be agreed upon before significant implementation work begins.

Thank you for helping make llmsec safer, faster, and more useful.
