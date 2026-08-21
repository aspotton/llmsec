# Prompt injection

Prompt injection attempts to cause an LLM to follow attacker-supplied instructions that conflict with the application's intended task or policy.

V0.1 contains a small heuristic detector only to bootstrap the runtime architecture and regression suite. It should not be described as a robust semantic defense.

The roadmap calls for a compact, calibrated, multi-task local model trained and evaluated against character transformations, semantic attacks, hard benign negatives, role impersonation, and adaptive attacks.
