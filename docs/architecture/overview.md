# Architecture overview

V0.1 deliberately implements only the first part of the longer-term security architecture.

```text
text
  |
  v
SecurityContext
  |
  v
ContentViews
  |
  +---- Unicode detector
  +---- encoding detector
  +---- secret detector
  +---- context anomaly detector
  +---- bootstrap injection detector
  |
  v
Findings
  |
  v
Policy
  |
  v
Decision
```

Alongside this text pipeline, a separate commit-gate seam authorizes proposed tool calls: `llmsec.actions.ReferenceMonitor` decides over a host-declared tool registry, granted capabilities, digest-bound approvals, and (optionally, tightening-only) findings, producing an `AuthorizationDecision` instead of a content `Decision`. The two paths share the detector vocabulary but not the decision type: admitting content and committing an action are different questions. See [Tool authorization](../concepts/tool-authorization.md).

The future architecture adds provenance/authority, source-influence controls, memory controls, streaming, long-context aggregation, and project-trained compact classifiers without replacing this core flow.

The V0.1 implementation keeps these seams explicit so future layers can be composed rather than forcing a rewrite.
