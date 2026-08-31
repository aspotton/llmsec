"""Duck-typed OpenAI-compatible chat client adapter.

Wraps any object exposing the OpenAI surface ``chat.completions.create``
(OpenAI, Azure OpenAI, LiteLLM, vLLM/Ollama compat servers). This module never
imports ``openai``/``anthropic`` or any other SDK: the wrapped client is
duck-typed, so the security runtime adds no provider dependencies. The
per-call primitives (decision mapping, streaming holdback) live in
``llmsec.integrations._openai_compat_stream``, split at the LOC review ceiling;
``GuardViolation`` and ``Mode`` are re-exported from there.

Scope ceiling: post-generation gating is NOT applied in ``mode="gate"`` (the
output phase is inspected only in ``block``/``sanitize`` modes, see
``_MODES_OUTPUT``). Applications that need gate-style output control call
``guard.inspect_model_output()`` themselves and run their own handler.

Streaming (``stream=True``) holds back output: chunk objects are buffered and
their concatenated delta text scanned in ``holdback``-sized windows before any
chunk is released (guarantees and ceilings documented in the stream module).
``mode="sanitize"`` refuses streaming outright -- already-yielded text cannot
be rewritten -- and ``gate`` mode streams pass through unscanned.
"""

import inspect
from collections.abc import Callable
from functools import partial, wraps
from typing import Any, Final

from llmsec.core import Decision, Stage, Trust
from llmsec.guard import Guard
from llmsec.integrations._openai_compat_stream import (
    GuardViolation as GuardViolation,
)
from llmsec.integrations._openai_compat_stream import (
    Mode as Mode,
)
from llmsec.integrations._openai_compat_stream import (
    _AGuardedStream,
    _apply_output_replacement,
    _assistant_text,
    _extract_input_text,
    _GuardedStream,
    _handle,
    _substitute_last,
)

_ALL_MODES: Final[frozenset[str]] = frozenset(("block", "sanitize", "gate"))

# Modes whose model output is inspected. Gate mode deliberately skips the
# output phase (see the scope-ceiling note in the module docstring).
_MODES_OUTPUT: Final[frozenset[str]] = frozenset(("block", "sanitize"))


def default_confirm_handler(decision: Decision) -> bool:
    """Decline every CONFIRM decision (fail closed).

    Override via ``GuardedChatClient(confirm_handler=...)`` to wire a human or
    application gate; returning ``True`` approves the call.
    """
    del decision
    return False


def _pre_input(
    guard: Guard,
    kwargs: dict[str, Any],
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> dict[str, Any]:
    """Inspect outgoing messages; return kwargs, substituting on sanitize.

    Ceiling: DefaultPolicy wires no rewriter (substituted content equals the
    original), and last-message replacement of the joined inspection text is
    single-message-correct only -- the same ceiling as the no-SANITIZE-emission
    rule.
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
    return {**kwargs, "messages": _substitute_last(messages, replacement)}


async def _apre_input(
    guard: Guard,
    kwargs: dict[str, Any],
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> dict[str, Any]:
    """Async twin of ``_pre_input``: awaits ``guard.ainspect`` (sync inspect is loop-hostile)."""
    messages = kwargs.get("messages")
    if messages is None:
        return kwargs
    decision = await guard.ainspect(
        _extract_input_text(messages), stage=Stage.USER_INPUT, trust=Trust.UNKNOWN
    )
    replacement = _handle(decision, phase="input", mode=mode, confirm_handler=confirm_handler)
    if replacement is None:
        return kwargs
    return {**kwargs, "messages": _substitute_last(messages, replacement)}


def _post_output(
    guard: Guard,
    response: object,
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> None:
    """Inspect assistant text; block raises, sanitize rewrites in place."""
    text = _assistant_text(response)
    if text is None:
        return
    decision = guard.inspect(text, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
    _apply_output_replacement(response, decision, mode=mode, confirm_handler=confirm_handler)


async def _apost_output(
    guard: Guard,
    response: object,
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> None:
    """Async twin of ``_post_output``: awaits ``guard.ainspect`` for the output phase."""
    text = _assistant_text(response)
    if text is None:
        return
    decision = await guard.ainspect(text, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
    _apply_output_replacement(response, decision, mode=mode, confirm_handler=confirm_handler)


def _create(
    *,
    inner: Callable[..., Any],  # ponytail: SDK duck-type seam (sync or async callable)
    guard: Guard,
    mode: Mode,
    holdback: int,
    confirm_handler: Callable[[Decision], bool],
    **kwargs: Any,  # ponytail: SDK duck-type seam (caller kwargs passthrough)
) -> Any:  # ponytail: result or awaitable, per the wrapped create's own kind
    """Run one guarded call: dispatch on async-ness, then on the stream flag.

    Sanitize + streaming is refused synchronously here (already-yielded text
    cannot be rewritten), before any coroutine or iterator is constructed.
    """
    stream = bool(kwargs.get("stream"))
    if stream and mode == "sanitize":
        raise ValueError("llmsec: sanitize mode requires non-streaming")
    if inspect.iscoroutinefunction(inner):
        return _acreate(
            inner=inner,
            guard=guard,
            mode=mode,
            holdback=holdback,
            confirm_handler=confirm_handler,
            **kwargs,
        )
    kwargs = _pre_input(guard, kwargs, mode=mode, confirm_handler=confirm_handler)
    response = inner(**kwargs)
    if stream:
        if mode not in _MODES_OUTPUT:
            return response  # gate mode: output phase is never inspected

        def scan(text: str) -> None:
            decision = guard.inspect(text, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
            _handle(decision, phase="output", mode=mode, confirm_handler=confirm_handler)

        return _GuardedStream(response, scan=scan, holdback=holdback)
    if mode in _MODES_OUTPUT:
        _post_output(guard, response, mode=mode, confirm_handler=confirm_handler)
    return response


async def _acreate(
    *,
    inner: Callable[..., Any],  # ponytail: SDK duck-type seam (async callable)
    guard: Guard,
    mode: Mode,
    holdback: int,
    confirm_handler: Callable[[Decision], bool],
    **kwargs: Any,  # ponytail: SDK duck-type seam (caller kwargs passthrough)
) -> Any:  # ponytail: result or async-iterable stream
    """Async guarded call: both phases await ``guard.ainspect`` (sync guard is loop-hostile)."""
    kwargs = await _apre_input(guard, kwargs, mode=mode, confirm_handler=confirm_handler)
    response = await inner(**kwargs)
    if kwargs.get("stream"):
        if mode not in _MODES_OUTPUT:
            return response  # gate mode: output phase is never inspected

        async def scan(text: str) -> None:
            decision = await guard.ainspect(text, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
            _handle(decision, phase="output", mode=mode, confirm_handler=confirm_handler)

        return _AGuardedStream(response, scan=scan, holdback=holdback)
    if mode in _MODES_OUTPUT:
        await _apost_output(guard, response, mode=mode, confirm_handler=confirm_handler)
    return response


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
                    _create,
                    inner=inner_create,
                    guard=self._guarded._guard,
                    mode=self._guarded._mode,
                    holdback=self._guarded._holdback,
                    confirm_handler=self._guarded._confirm_handler,
                )
            )
        return getattr(self._inner, name)  # ponytail: SDK duck-type seam
