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

The future architecture adds provenance/authority, source-influence controls, tool/action authorization, memory controls, streaming, long-context aggregation, and project-trained compact classifiers without replacing this core flow.

The V0.1 implementation keeps these seams explicit so future layers can be composed rather than forcing a rewrite.
