"""Duck-typed OpenAI-compatible chat client adapter.

Wraps any object exposing the OpenAI surface ``chat.completions.create``
(OpenAI, Azure OpenAI, LiteLLM, vLLM/Ollama compat servers). This module never
imports ``openai``/``anthropic`` or any other SDK: the wrapped client is
duck-typed, so the security runtime adds no provider dependencies.

Scope ceiling: post-generation gating is NOT applied in ``mode="gate"`` (the
output phase is inspected only in ``block``/``sanitize`` modes, see
``_MODES_OUTPUT``). Applications that need gate-style output control call
``guard.inspect_model_output()`` themselves and run their own handler.

Streaming is not implemented in this revision: any ``stream=True`` call raises
``NotImplementedError`` (streaming holdback lands in the follow-up todo).
"""

from collections.abc import Callable, Sequence
from functools import partial, wraps
from typing import Any, Final, Literal

from llmsec.core import Decision, DecisionAction, Stage, Trust
from llmsec.guard import Guard

Mode = Literal["block", "sanitize", "gate"]

_ALL_MODES: Final[frozenset[str]] = frozenset(("block", "sanitize", "gate"))

# Modes whose model output is inspected. Gate mode deliberately skips the
# output phase (see the scope-ceiling note above).
_MODES_OUTPUT: Final[frozenset[str]] = frozenset(("block", "sanitize"))


class GuardViolation(RuntimeError):
    """Raised when policy stops a guarded call before or after the provider."""

    def __init__(self, *, reason: str, decision: Decision | None = None) -> None:
        super().__init__(f"llmsec {reason}")
        self.reason = reason
        self.decision = decision


def default_confirm_handler(decision: Decision) -> bool:
    """Decline every CONFIRM decision (fail closed).

    Override via ``GuardedChatClient(confirm_handler=...)`` to wire a human or
    application gate; returning ``True`` approves the call.
    """
    del decision
    return False


def _extract_input_text(messages: object) -> str:
    """Flatten an SDK ``messages`` value to inspectable text (defensive)."""
    if isinstance(messages, str):
        return messages
    if isinstance(messages, Sequence):
        return "\n".join(str(message.get("content", "")) for message in messages)
    return str(messages)


def _assistant_text(response: object) -> str | None:
    """Read ``choices[0].message.content`` from an SDK response, else None."""
    seam: Any = response  # ponytail: SDK duck-type seam
    try:
        return str(seam.choices[0].message.content)
    except (AttributeError, IndexError, TypeError):
        return None


def _handle(
    decision: Decision,
    *,
    phase: str,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> str | None:
    """Map a Decision onto this call: pass, substitute text, or raise.

    Returns replacement content when the caller's data should be rewritten,
    ``None`` to let the call proceed; raises ``GuardViolation`` otherwise.
    """
    if decision.allowed:
        return None
    match decision.action:
        case DecisionAction.CONFIRM:
            if mode == "sanitize":
                return decision.content
            if mode == "gate":
                if not confirm_handler(decision):
                    raise GuardViolation(reason="confirmation_required", decision=decision)
                return None
        case _:
            pass
    # BLOCK, a CONFIRM under mode="block", or any future non-allowed action.
    raise GuardViolation(reason=f"{phase}_blocked", decision=decision)


def _pre_input(
    guard: Guard,
    kwargs: dict[str, Any],
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> dict[str, Any]:
    """Inspect outgoing messages; return kwargs, substituting on sanitize.

    Substitution replaces the LAST mapping's content in a fully copied list:
    caller data is never mutated. Ceiling: DefaultPolicy wires no rewriter, so
    substituted content equals the inspected original text; and replacing the
    joined inspection text via the last message is only exact for
    single-message requests (multi-message sanitize would duplicate text).
    """
    messages = kwargs.get("messages")
    if messages is None:
        return kwargs
    decision = guard.inspect(
        _extract_input_text(messages), stage=Stage.USER_INPUT, trust=Trust.UNKNOWN
    )
    replacement = _handle(decision, phase="input", mode=mode, confirm_handler=confirm_handler)
    if replacement is None:
        return kwargs
    if isinstance(messages, str):
        return {**kwargs, "messages": replacement}
    if isinstance(messages, Sequence) and len(messages) > 0:
        copied: list[Any] = [dict(m) if isinstance(m, dict) else m for m in messages]
        if isinstance(copied[-1], dict):
            copied[-1] = {**copied[-1], "content": replacement}
            return {**kwargs, "messages": copied}
    return {**kwargs, "messages": replacement}


def _post_output(
    guard: Guard,
    response: object,
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> None:
    """Inspect assistant text; block raises, sanitize rewrites in place.

    SDK response models are mutable, so the substitution updates
    ``choices[0].message.content`` on the SAME response object.
    """
    text = _assistant_text(response)
    if text is None:
        return
    decision = guard.inspect(text, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
    replacement = _handle(decision, phase="output", mode=mode, confirm_handler=confirm_handler)
    if replacement is None:
        return
    seam: Any = response  # ponytail: SDK duck-type seam
    seam.choices[0].message.content = replacement


def _create_sync(
    *,
    inner: Callable[..., object],
    guard: Guard,
    mode: Mode,
    holdback: int,
    confirm_handler: Callable[[Decision], bool],
    **kwargs: Any,  # ponytail: SDK duck-type seam (caller kwargs passthrough)
) -> object:
    """Run one guarded non-streaming call; delegate streaming to the stub."""
    if kwargs.get("stream"):
        return _create_stream(
            inner=inner,
            guard=guard,
            mode=mode,
            holdback=holdback,
            confirm_handler=confirm_handler,
            **kwargs,
        )
    kwargs = _pre_input(guard, kwargs, mode=mode, confirm_handler=confirm_handler)
    response = inner(**kwargs)
    if mode in _MODES_OUTPUT:
        _post_output(guard, response, mode=mode, confirm_handler=confirm_handler)
    return response


def _create_stream(
    *,
    inner: Callable[..., object],
    guard: Guard,
    mode: Mode,
    holdback: int,
    confirm_handler: Callable[[Decision], bool],
    **kwargs: Any,  # ponytail: SDK duck-type seam (caller kwargs passthrough)
) -> object:
    """Streaming entry point; holdback streaming lands in the follow-up todo."""
    raise NotImplementedError("llmsec streaming guard mode is not implemented yet")


class GuardedChatClient:
    """Wrap an OpenAI-compatible client so every chat call is inspected.

    Attribute access delegates to the wrapped client except ``chat``, which
    routes through the guarded proxies. ``mode`` selects policy handling:
    ``block`` raises ``GuardViolation``, ``sanitize`` substitutes content where
    safe, ``gate`` routes CONFIRM decisions to ``confirm_handler``.
    """

    _client: Any  # ponytail: SDK duck-type seam (attribute-name dispatch proxy)
    _guard: Guard
    _mode: Mode
    _holdback: int
    _confirm_handler: Callable[[Decision], bool]

    def __init__(
        self,
        client: object,
        *,
        guard: Guard | None = None,
        mode: Mode = "block",
        holdback: int = 80,
        confirm_handler: Callable[[Decision], bool] = default_confirm_handler,
    ) -> None:
        if mode not in _ALL_MODES:
            raise ValueError(f"unknown mode {mode!r}")
        if holdback < 1:
            raise ValueError("holdback must be >= 1")
        if getattr(client, "_WRAPPED", False):
            raise ValueError("already guarded")
        object.__setattr__(self, "_WRAPPED", True)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_guard", guard if guard is not None else Guard.default())
        object.__setattr__(self, "_mode", mode)
        object.__setattr__(self, "_holdback", holdback)
        object.__setattr__(self, "_confirm_handler", confirm_handler)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)  # ponytail: SDK duck-type seam

    @property
    def chat(self) -> "_Chat":
        """Guarded ``chat`` namespace proxy."""
        return _Chat(self)


class _Chat:
    """Proxy for the wrapped client's ``chat`` namespace."""

    _guarded: GuardedChatClient
    _inner: Any  # ponytail: SDK duck-type seam

    def __init__(self, guarded: GuardedChatClient) -> None:
        object.__setattr__(self, "_guarded", guarded)
        object.__setattr__(self, "_inner", guarded._client.chat)

    def __getattr__(self, name: str) -> Any:
        # ponytail: name-branch proxy; real SDK seam classes if a provider
        # exposes non-identical chat paths.
        if name == "completions":
            return _Completions(self._guarded, self._inner.completions)
        return getattr(self._inner, name)  # ponytail: SDK duck-type seam


class _Completions:
    """Proxy for the wrapped client's ``chat.completions`` namespace."""

    _guarded: GuardedChatClient
    _inner: Any  # ponytail: SDK duck-type seam

    def __init__(self, guarded: GuardedChatClient, inner_completions: object) -> None:
        object.__setattr__(self, "_guarded", guarded)
        object.__setattr__(self, "_inner", inner_completions)

    def __getattr__(self, name: str) -> Any:
        if name == "create":
            inner_create = self._inner.create
            # wraps() pins __wrapped__ on the exposed callable only; that is
            # the sanctioned attr (callers see the SDK create's signature).
            return wraps(inner_create)(
                partial(
                    _create_sync,
                    inner=inner_create,
                    guard=self._guarded._guard,
                    mode=self._guarded._mode,
                    holdback=self._guarded._holdback,
                    confirm_handler=self._guarded._confirm_handler,
                )
            )
        return getattr(self._inner, name)  # ponytail: SDK duck-type seam
