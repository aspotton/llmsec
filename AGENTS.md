# Repository instructions for coding agents

`llmsec` is security-sensitive software. Keep changes small, testable, and consistent with the documented threat model.

## Before changing code

Read the closest `AGENTS.md` in the subtree you are editing. For architectural or security-sensitive changes also read:

- `docs/architecture/design-principles.md`
- `docs/architecture/overview.md`
- `docs/security/threat-model.md`
- `docs/security/limitations.md`
- `docs/development/testing.md`

## Repository-wide invariants

- The LLM is not a trusted authorization component.
- Detection is defense-in-depth, not the final security boundary.
- Trusted security metadata must not be inferred from or embedded solely in untrusted natural-language text.
- Use typed Python security primitives where the project defines them. Do not introduce free-form string identifiers for stages, trust levels, severities, or decisions.
- Detectors return `Finding` objects. Policies produce `Decision` objects.
- Detectors must not mutate shared source content.
- Build shared `ContentViews` once and reuse them instead of repeating normalization or decoding in each detector.
- Keep expensive operations bounded and suitable for low-latency execution.
- Production runtime dependencies must remain separate from training/evaluation dependencies.
- Never silently download model artifacts during request handling.
- Security behavior changes require regression tests.
- Security-relevant Unicode in Python source should normally use explicit escapes or code-point construction rather than visually ambiguous/invisible literal characters; see `docs/development/unicode-fixtures.md`.
- Do not disable CI, type checks, lint rules, or security tests merely to make a patch pass.

## Documentation map

- Human overview: `README.md`
- Architecture: `docs/architecture/`
- Concepts and public API: `docs/concepts/`
- Usage guides: `docs/guides/`
- Security progress evidence (eval corpus and tripwire runner): `evals/README.md`
- Threats and limitations: `docs/security/`
- Development/CI conventions: `docs/development/`
- Future architecture and phased work: `docs/roadmap/`

When code changes a documented contract, update the canonical document rather than duplicating explanations into `AGENTS.md`.
