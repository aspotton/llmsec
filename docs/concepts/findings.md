# Findings and decisions

A `Finding` records evidence:

- detector name;
- category;
- confidence;
- severity;
- human-readable message;
- optional spans and structured properties.

A `Decision` records policy output:

- action;
- original/current content;
- findings;
- aggregate risk;
- optional diagnostics.

Keeping these objects separate lets future policies react differently to the same finding depending on stage, provenance, effect, and deployment requirements.
