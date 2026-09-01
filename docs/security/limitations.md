# Security limitations

V0.1 is a scaffold and useful local inspection runtime, not a complete LLM security boundary.

Important limitations:

- the prompt-injection detector is heuristic, not a trained semantic model;
- Unicode coverage is intentionally incomplete;
- encoded-content inspection is currently limited to bounded printable Base64 candidates;
- the reference monitor authorizes tool calls against the host's declared registry only; it cannot audit what a tool actually does (see "Action authorization limits" below);
- the OpenAI-compatible wrapper (`llmsec.integrations.openai_compat`) inspects text at one integration seam; it is not a tool/action reference monitor;
- there is no provenance/authority or data-lineage engine yet;
- long-context fragmentation is not solved;
- streaming holdback exists only in the OpenAI-compatible wrapper's chunk-window scan; the core `Guard` API has no token-level or streaming scanning;
- the default policy emits only ALLOW, CONFIRM, and BLOCK; CONFIRM requires an application or human check before use, and SANITIZE, QUARANTINE, and ESCALATE are still never emitted;
- profile presets (`Guard.from_profile`) tune policy thresholds only; they do not yet change the detector set;
- no classifier can be assumed robust against an adaptive attacker merely because it performs well on a fixed benchmark.

Applications should not interpret `DecisionAction.ALLOW` as proof that content is safe. It means the configured V0.1 checks did not trigger a blocking rule.

## Action authorization limits

The reference monitor (`llmsec.actions`, `Guard.authorize_tool_call`, `llmsec authorize`) decides over host-declared metadata, not observed behavior. Its guarantees are conditional:

- **Registry mis-declaration.** The monitor trusts the effects the host declares for each tool; it cannot audit what a tool actually does when called. A tool declared READ-only that in fact writes, egresses, or executes is authorized as a read. The one signal the monitor can see is structural self-inconsistency (a READ-declared tool carrying a non-`GENERIC` role param surfaces as `suspected_misdeclaration`). A host that *uniformly* mis-declares a tool's effects, with parameters that look consistent, is undetectable from the declaration alone: the registry is the trust root, and a lying trust root has no cross-check inside this runtime.
- **TOCTOU (commit what you authorized).** An approval and a decision bind to one `proposal_sha256`, the SHA-256 of the canonical encoding of the exact call. That binding holds only if the host commits EXACTLY the call it authorized. Before triggering the effect, recompute `proposal_sha256(call)` and compare it with `decision.proposal_sha256`; commit only on equality. Reconstructing an "equivalent" call from freshly fetched values produces a different digest and voids the approval. The in-process argument snapshot (`MappingProxyType`) defends against post-decision mutation of the caller's dict, not against the host building a different call.
- **Cross-process TOCTOU is out of scope.** llmsec observes no tool execution. If the tool the monitor approved is not the tool the process actually runs (argument re-resolution, symlink/shell expansion, a swapped binary), that gap lives in the host integration, not here. Digest-binding above is the documented mitigation, not enforcement.
- **Registry mutation after serve start.** The monitor reads the registry live; it does not freeze it. Adding, removing, or re-declaring tools after a monitor is serving changes every later decision, including flipping a previously-deniable tool to allowed. Treat the registry as immutable for a serve lifetime: build it once, restart to change it.
- **Detection escalation is input-dependent.** The `findings` argument only tightens (HIGH+ forces DENY, MEDIUM floors ALLOW to REQUIRE_APPROVAL) and never grants. But escalation is only as good as the findings the host supplies: a host that passes no findings gets pure structural authorization, which is the intended fail-open-of-detection property, not a bypass.

The `llmsec authorize` CLI and its `--registry`/`--capabilities` JSON files are a demo convenience, not a production trust path; a production host wires `ReferenceMonitor` to configuration it controls.
