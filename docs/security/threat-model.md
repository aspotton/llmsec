# Threat model

llmsec assumes that natural-language content supplied to an LLM can be adversarial and that detection can fail.

## V0.1 in scope

- direct prompt-injection patterns;
- indirect injection in retrieved/tool-result text;
- invisible/direction-changing Unicode controls;
- encoded printable payloads;
- obvious secret material;
- simple context-padding anomalies.

## Architectural future scope

- role confusion and role impersonation;
- long-context and fragmented attacks;
- tool-call and parameter manipulation;
- unauthorized external effects;
- forged user approval;
- provenance and authority confusion;
- source-influence violations;
- persistent memory manipulation;
- streaming leakage before a block decision;
- adaptive attacks against the released defense.

## Core assumption

The LLM is treated as an untrusted reasoning component. A future reference monitor will enforce capabilities and effects outside the LLM so that detector failure does not automatically become action authorization.
