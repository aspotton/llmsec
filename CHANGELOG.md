# Changelog

## 0.1.0 - Unreleased

Tool and action security (roadmap 02, reference-monitor core):

- New `llmsec.actions` package: typed `EffectClass`/`ParamRole`/`ParamKind`/`AuthorizationAction` vocabularies, `ToolSpec`/`ToolCall`/`Capability`/`Approval`/`AuthorizationDecision` value types, a host-declared `ToolRegistry` with a schema-checked JSON loader, and the deterministic `ReferenceMonitor.authorize` decision table (no detector, model, network, or payload-approval read path).
- Digest-bound approvals: `proposal_sha256` is the SHA-256 of the canonical JSON of the exact call; approval replay against any other call denies (`approval_mismatch`), and `ToolCall` snapshots its arguments so post-construction mutation cannot shift the digest. `AuthorizationDecision.commit_allowed` is true for `ALLOW` only.
- `Guard.authorize_tool_call(call, approval, findings)` commit-gate facade; findings are a one-way tightening input (HIGH+ forces DENY, MEDIUM floors ALLOW). A `Guard` with no monitor denies by default (`no_monitor`) and never raises; the existing `inspect` paths are unchanged.
- CLI: `llmsec authorize --registry PATH.json [--capabilities PATH.json] [--approval-sha HEX --approver NAME]` reads one call from stdin; exit 0 allow, 2 deny, 3 require_approval (argparse usage errors also exit 2, a documented collision). The JSON files are a demo convenience, not a production trust path.
- Seven security lock-ins in `tests/security/test_action_regressions.py`: detection never grants a capability, findings only escalate, model-claimed approval in the payload is inert, unregistered/schema-mismatch/missing-capability deny, READ fail-open is schema-bounded, and an unconfigured Guard denies.
- Documentation: canonical `docs/concepts/tool-authorization.md`, a new "Action authorization limits" section in `docs/security/limitations.md` (registry mis-declaration, TOCTOU/digest-binding, registry mutation, detection input-dependence), and the four tool-call/parameter/effect/approval threat rows moved into a "Now enforced (conditional on a truthful registry)" section of `docs/security/threat-model.md`. Framework/MCP adapters deferred to roadmap 10.

Adaptive evaluation (roadmap 08, text-detector scope):

- Seeded mutation-ladder generator `evals/gen_adaptive.py` + `evals/mutations.py`: deterministic character/encoding transforms over the fixed attack bases, pinned at seed 20260831 (354 rows) and byte-checked via `--regenerate` in CI.
- Adaptive runner `evals/run_adaptive.py`: measured held-in/held-out split, held-in recall floors (1.0) plus benign FP budget as always-on tripwires, `--gate` adds gap-regression against `evals/adaptive/gap-baseline.json`; undetected held-out rows published to `evals/adaptive/UNDETECTED.md` (142 gaps at the pin). Latency is report-only until `--latency-fail-ms` is set.
- CI: adaptive gate in `security-regression.yml`, regen byte-check in the `ci.yml` Python 3.13 leg. Transformation-coverage and gap publication only; agent-level and multi-turn/memory/tool/long-context evaluation remain open.

Initial project scaffold:

- Typed stages, trust levels, findings, decisions, and security context.
- Immutable shared content views.
- Async-first detector protocol and concurrent execution.
- Built-in Unicode, encoded-content, secret, context-anomaly, and heuristic injection detectors.
- Default policy and convenience inspection methods.
- Default policy emits CONFIRM for findings at or above `confirm_threshold` (0.75) that meet the severity gate.
- `Guard.from_profile(Profile.CHAT | RAG | AGENT)` configures per-profile policy presets; `Guard.default(policy=...)` accepts an explicit policy override.
- Eval baseline corpus (54 cases across four attack families plus benign) and `evals/run_eval.py`, a stdlib fixed-benchmark tripwire runner with recall/false-positive floors.
- Behavior change: a `Severity.HIGH` fake-authority finding at confidence 0.89 now resolves CONFIRM instead of the previous silent ALLOW.
- `llmsec.integrations.openai_compat.GuardedChatClient`: dependency-free, duck-typed OpenAI-compatible wrapper inspecting `chat.completions.create` (sync/async, block/sanitize/gate modes, streaming holdback); `GuardViolation` exported from `llmsec`.
- CLI: `llmsec scan --profile <chat|rag|agent>` applies the profile policy presets.
- CLI, examples, tests, GitHub Actions, documentation hierarchy, and roadmap.
