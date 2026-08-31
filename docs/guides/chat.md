# Chat applications

Use `inspect_user_input()` before passing user text to the model and `inspect_model_output()` before returning model output when output scanning is desired.

V0.1 does not attempt to infer authorization from chat content. Future agent/action controls will live outside the model conversation.

OpenAI-shaped stacks can wrap their client in [`GuardedChatClient`](openai-compat.md) instead of calling these methods directly.
