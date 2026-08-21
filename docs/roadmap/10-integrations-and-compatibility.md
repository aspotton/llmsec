# Integrations and compatibility

Keep the security core framework-agnostic. Integrations should be thin adapters over the same typed `Guard`, event, finding, policy, and future action-authorization APIs.

Planned integration targets include:

- OpenAI and Anthropic client wrappers;
- generic ASGI/FastAPI middleware;
- LangChain and LlamaIndex;
- MCP tool/result boundaries;
- Pydantic-style tool schemas;
- a local HTTP/Unix-socket sidecar for non-Python applications.

A future LLM Guard compatibility package can adapt legacy input/output scanners where practical while preserving llmsec's immutable-content and findings-first execution model. Compatibility must not force the core runtime to reproduce sequential mutation or scanner-order-dependent behavior.
