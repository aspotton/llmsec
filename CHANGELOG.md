# Changelog

## 0.1.0 - Unreleased

Initial project scaffold:

- Typed stages, trust levels, findings, decisions, and security context.
- Immutable shared content views.
- Async-first detector protocol and concurrent execution.
- Built-in Unicode, encoded-content, secret, context-anomaly, and heuristic injection detectors.
- Default policy and convenience inspection methods.
- Default policy emits CONFIRM for findings at or above `confirm_threshold` (0.75) that meet the severity gate.
- `Guard.from_profile(Profile.CHAT | RAG | AGENT)` configures per-profile policy presets; `Guard.default(policy=...)` accepts an explicit policy override.
- Behavior change: a `Severity.HIGH` fake-authority finding at confidence 0.89 now resolves CONFIRM instead of the previous silent ALLOW.
- CLI, examples, tests, GitHub Actions, documentation hierarchy, and roadmap.
