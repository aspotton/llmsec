# Design principles

These are intended to remain stable as the implementation grows.

1. **The LLM is not a trusted authorization component.** It may propose actions; host-side security code decides whether actions are permitted.
2. **Detection is defense-in-depth.** A low detector score must never grant a capability that was not already authorized.
3. **Trusted metadata stays outside untrusted language.** Application-known stage, provenance, authority, capability, and approval state must not depend on the model accepting textual role labels.
4. **Use typed security primitives.** Python APIs use enums/value objects for defined concepts such as `Stage`, `Trust`, `Severity`, and `DecisionAction`.
5. **Detectors report; policy decides.** Detection code produces evidence. Policy decides allow/block/sanitize/confirm/escalate behavior.
6. **Content is immutable during inspection.** Multiple detectors receive shared views of the same source. Sanitization, when added, is applied after findings are collected.
7. **Preprocessing is shared.** Unicode normalization, decoding, tokenization, and markup extraction should be computed once where possible.
8. **Independent work is parallelizable.** The runtime should minimize additive scanner latency.
9. **Expensive work is bounded.** Decoding depth, candidate size, model context, timeouts, and concurrency require explicit limits.
10. **Local execution is first-class.** Default inspection should not require a remote service or generative-model call.
11. **Training is not a runtime dependency.** Model-building tools stay outside the production dependency graph.
12. **Provenance, authority, data lineage, and source influence are distinct.** Future agent security must preserve these concepts rather than reducing them to one generic trust score.
13. **Approval is application state.** A model-generated statement that approval occurred is not approval.
14. **Security behavior is testable.** Regressions should fail CI on pushes and pull requests.
