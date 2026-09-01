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

## Status

The core reference monitor shipped in roadmap 02:

- typed effect classes, parameter roles/kinds, and authorization actions (`llmsec.actions`);
- a host-declared tool registry with a schema-checked JSON loader and a mis-declaration inconsistency surface;
- the deterministic `ReferenceMonitor.authorize` decision table (structural steps 1-6 plus a one-way findings escalation), producing a dedicated `AuthorizationDecision` whose `commit_allowed` is true only for `ALLOW`;
- digest-bound approvals (`proposal_sha256`) and the `Guard.authorize_tool_call` facade (deny-by-default without a monitor);
- a demo `llmsec authorize` CLI and security regression lock-ins.

Guarantees are conditional on a truthful registry; the monitor trusts declared effects and cannot audit a tool's real behavior. See [Tool authorization](../concepts/tool-authorization.md) and [Security limitations](../security/limitations.md).

Framework and MCP adapters are deferred to [roadmap 10](10-integrations-and-compatibility.md): thin integrations layered over this typed API rather than a second authorization surface.
