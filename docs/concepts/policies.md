# Policies

Policies turn findings into a single `DecisionAction`. The shipped `DefaultPolicy` emits only `ALLOW`, `CONFIRM`, or `BLOCK`; it never emits `SANITIZE`, `QUARANTINE`, or `ESCALATE`.

Blocking: any finding at or above `block_threshold` (default `0.90`) whose severity is at or above `minimum_block_severity` (default `Severity.HIGH`) produces `BLOCK`. Confirming: when nothing blocks, any finding at or above `confirm_threshold` (default `0.75`) that also meets `minimum_block_severity` produces `CONFIRM`. Everything else produces `ALLOW`, with the findings retained alongside the allowed content.

`CONFIRM` means the application must not use the content without a human or application-level check. `Decision.allowed` is `False` for `CONFIRM`, so existing callers that gate on `allowed` fail closed instead of treating confirmation as a pass.

One behavior change is worth calling out: a `Severity.HIGH` fake-authority finding at confidence `0.89` previously resolved `ALLOW` and now resolves `CONFIRM`. That operating point sits below `block_threshold`, so it used to pass silently.

This is a bootstrap policy, not the final policy system. Future policy work adds stage-aware thresholds, sanitization patches, escalation, effect-aware rules, and source-influence constraints.
