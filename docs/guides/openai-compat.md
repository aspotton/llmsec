# OpenAI-compatible wrapper

`GuardedChatClient` wraps any object with the OpenAI `chat.completions.create` surface (OpenAI, Azure OpenAI, LiteLLM, vLLM/Ollama compat servers). No extra install: no SDK is imported by `llmsec`; the client is duck-typed. It is the first of the "thin adapters over the same typed `Guard` API" planned in [roadmap 10](../roadmap/10-integrations-and-compatibility.md).

```python
from openai import OpenAI  # your SDK, not llmsec's dependency
from llmsec.integrations.openai_compat import GuardedChatClient, GuardViolation

client = GuardedChatClient(OpenAI())  # block mode: default Guard
try:
    response = client.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": text}]
    )
except GuardViolation as exc:
    handle(exc.reason, exc.decision)  # keyword-only attrs; .decision may be None mid-stream
```

Gate mode routes CONFIRM decisions to a handler (return `True` to proceed; the default handler declines):

```python
client = GuardedChatClient(OpenAI(), mode="gate", confirm_handler=lambda d: ask_user(d))
```

Streaming buffers chunks and scans their text in `holdback`-sized windows before releasing any chunk; a violation raises mid-iteration:

```python
client = GuardedChatClient(OpenAI(), holdback=80)
for chunk in client.chat.completions.create(..., stream=True):  # raises GuardViolation
    show(chunk)
```

## What it does not do

This is an inspection seam, not action authorization (roadmap 02 is open). The wrapper covers only `chat.completions.create`. For these paths call `guard.inspect(...)` at that boundary yourself (see [Guard concepts](../concepts/guard.md)):

- Responses API, `.parse()`, and `.with_raw_response` calls are passed through unguarded.
- Tool-call arguments are not inspected as actions; inspect tool results with `guard.ainspect_tool_result(...)`.
- In `gate` mode model output is not inspected or gated at all (`block`/`sanitize` do inspect output).
- `mode="sanitize"` refuses `stream=True`; already-yielded text cannot be rewritten.
