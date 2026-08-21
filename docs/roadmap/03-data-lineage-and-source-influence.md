# Data lineage and source influence

Track which sources were able to influence derived values and proposed action parameters.

Planned lineage strengths include exact extraction, deterministic derivation, and conservative influence envelopes around generative-model calls.

A core policy example: untrusted retrieved data may contribute to an email body but may not autonomously select an external destination unless explicitly allowed or confirmed by the user/application.
