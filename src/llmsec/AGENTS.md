# Runtime package instructions for coding agents

This subtree is the production runtime and must remain lightweight.

Rules:

- Python 3.11+ is the supported language baseline.
- Do not add PyTorch, Transformers, dataset libraries, or training frameworks to the base runtime.
- Prefer stdlib and small native-backed optional dependencies where justified by measured benefit.
- Public APIs should use typed security primitives rather than arbitrary string values.
- Sync APIs are convenience wrappers; async APIs are the primary composition surface for servers and agents.
- Avoid hidden network access, background downloads, or unbounded recursive decoding.
- Preserve immutable input/content-view semantics.
- Represent security-sensitive Unicode constants with explicit escapes, ranges, categories, or code-point construction rather than ambiguous/invisible literal characters.
- A detector must never directly authorize or block an action; it reports evidence to policy.

Read:

- `docs/architecture/execution-model.md`
- `docs/architecture/content-pipeline.md`
- `docs/development/api-design.md`
- `docs/development/unicode-fixtures.md` when changing Unicode handling or fixtures
