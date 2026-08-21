# Stages

A security decision depends on where content appears, not only on the string itself.

V0.1 defines typed stages:

- `Stage.USER_INPUT`
- `Stage.RETRIEVAL_DOCUMENT`
- `Stage.TOOL_RESULT`
- `Stage.MODEL_OUTPUT`

The Python API intentionally uses `Stage` rather than arbitrary strings. Configuration formats may serialize these values as strings at a boundary, but parsing should validate and convert them immediately.

Future stages include memory writes, tool calls, and action commits.
