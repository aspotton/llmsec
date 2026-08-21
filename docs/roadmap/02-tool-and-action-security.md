# Tool and action security

Add a host-side reference monitor for proposed tool calls.

Planned concepts:

- typed capabilities;
- tool registry and argument schemas;
- effect classes such as read, external write, deletion, data egress, code execution, financial, permission change, and memory persistence;
- parameter roles such as destination, resource selector, executable, financial value, and payload;
- deterministic authorization before action commit;
- impact-aware fail-open/fail-closed behavior.

The LLM proposes actions; the security runtime authorizes them.
