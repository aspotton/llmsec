# Threat model

llmsec assumes that natural-language content supplied to an LLM can be adversarial and that detection can fail.

## V0.1 in scope

- direct prompt-injection patterns;
- indirect injection in retrieved/tool-result text;
- invisible/direction-changing Unicode controls;
- encoded printable payloads;
- obvious secret material;
- simple context-padding anomalies.

## Now enforced (conditional on a truthful registry)

The host-side reference monitor (`llmsec.actions`) enforces these outside the LLM, provided the tool registry truthfully declares each tool's effects. See [Security limitations](limitations.md) for the mis-declaration and TOCTOU conditions.

| Threat | Enforcement |
| --- | --- |
| Tool-call manipulation | Unknown tools DENY (`unregistered_tool`); arguments must satisfy the host-declared schema or DENY (`schema_violation`); the call an approval bound to is digest-checked, so a modified replay DENIES (`approval_mismatch`). |
| Parameter manipulation | Declared `ParamKind`/`ParamRole` schema checks deny wrong-typed, unknown, or over-length arguments; exact type matching means `true` never passes as a count. READ-declared tools with risk-role params surface as `suspected_misdeclaration`. |
| Unauthorized external effects | Every non-READ effect class is fail-closed: without a host-granted capability the call DENIES (`missing_capability`). Detector findings can tighten this (HIGH forces DENY) but can never grant a capability or satisfy an approval. |
| Forged user approval | Approval is a host-supplied `Approval` bound to the SHA-256 of one exact call, never parsed from call arguments; approval fields inside a model-produced payload are inert; `requires_approval` cannot be bypassed by omitting the approval argument (REQUIRE_APPROVAL, not ALLOW). |

A `Guard` with no monitor configured DENIES every call (`no_monitor`): the default state is no authority, not full authority.

## Architectural future scope

- role confusion and role impersonation;
- long-context and fragmented attacks;
- provenance and authority confusion;
- source-influence violations;
- persistent memory manipulation;
- streaming leakage before a block decision;
- adaptive attacks against the released defense.

## Core assumption

The LLM is treated as an untrusted reasoning component. The reference monitor enforces capabilities and effects outside the LLM so that detector failure does not automatically become action authorization.
