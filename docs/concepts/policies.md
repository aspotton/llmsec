# Policies

V0.1 ships a deliberately small default policy: high-severity findings at or above the configured confidence threshold block; other findings are retained while content is allowed.

This is a bootstrap policy, not the final policy system. Future policy work adds stage-aware thresholds, sanitization patches, escalation, confirmations, effect-aware rules, and source-influence constraints.
