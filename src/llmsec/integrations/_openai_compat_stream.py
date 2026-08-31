"""Leaf primitives for the OpenAI-compatible adapter: decision mapping and streaming.

Split out of ``openai_compat.py`` at the 250-LOC review ceiling; the public
proxy surface lives there and re-exports ``GuardViolation`` from here. This
module imports nothing from ``openai_compat`` (one-way dependency) and never
imports any provider SDK.

Streaming holdback (buffer-then-scan-then-yield): chunk OBJECTS are buffered
and yielded whole (never sliced); only the decision to release them is gated.
The ``scan`` callbacks are injected by the caller and raise ``GuardViolation``
on a policy stop. Guarantees (pinned by the todo-14(h) contract tests):

- A COMPLETE violation is never fully released when it fits inside the first
  scan window (first chunk smaller than ``holdback``).
- Per-raise unscanned residue is below ``holdback`` characters.
- Clean prefix text released before a later violation IS legitimately out
  (bounded by the scan cadence).

``ponytail: sliding tail window; per-pattern-length windows if detector patterns
ever exceed holdback``. Documented ceiling: a pattern longer than ``holdback``,
or a single chunk >= holdback ending mid-phrase, can span scan windows
undetected.
"""

from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Sequence,
)
from typing import Any, Literal

from llmsec.core import Decision, DecisionAction

Mode = Literal["block", "sanitize", "gate"]


class GuardViolation(RuntimeError):
    """Raised when policy stops a guarded call before or after the provider."""

    def __init__(self, *, reason: str, decision: Decision | None = None) -> None:
        super().__init__(f"llmsec {reason}")
        self.reason = reason
        self.decision = decision


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


def _substitute_last(messages: object, replacement: str) -> Any:
    """Return messages with the LAST mapping's content replaced (caller data untouched)."""
    if isinstance(messages, str):
        return replacement
    if isinstance(messages, Sequence) and len(messages) > 0:
        copied: list[Any] = [dict(m) if isinstance(m, dict) else m for m in messages]
        if isinstance(copied[-1], dict):
            copied[-1] = {**copied[-1], "content": replacement}
            return copied
    return replacement


def _apply_output_replacement(
    response: object,
    decision: Decision,
    *,
    mode: Mode,
    confirm_handler: Callable[[Decision], bool],
) -> None:
    """Act on an output-phase decision; sanitize updates the SAME response
    object in place (SDK response models are verified mutable)."""
    replacement = _handle(decision, phase="output", mode=mode, confirm_handler=confirm_handler)
    if replacement is None:
        return
    seam: Any = response  # ponytail: SDK duck-type seam
    seam.choices[0].message.content = replacement


def _delta_text(chunk: object) -> str:
    """Concatenate delta content of one streaming chunk (SDK delta idiom).

    Chunks with empty ``choices`` (the terminal usage chunk) or a delta with no
    content read as the empty string.
    """
    parts: list[str] = []
    for choice in getattr(chunk, "choices", []):
        delta = getattr(choice, "delta", None)
        content = getattr(delta, "content", None) if delta is not None else None
        if content:
            parts.append(str(content))
    return "".join(parts)


def _carry(scanned: str, holdback: int) -> str:
    """Trailing ``holdback - 1`` chars of a scanned window, for cross-window matching."""
    return scanned[-(holdback - 1) :] if holdback > 1 else ""


class _GuardedStream:
    """Sync chunk iterator that scans every ``holdback``-sized window before release.

    ``tail`` (scanned-clean text held for cross-window matching) plus the
    buffered chunks' ``text`` are scanned as ONE string once their combined
    length reaches ``holdback``; violation raises before anything is yielded,
    otherwise the buffered chunk objects are yielded whole. On exhaustion the
    final ``tail + text`` is scanned and remaining chunks flushed.
    """

    def __init__(
        self,
        upstream: Iterable[object],
        *,
        scan: Callable[[str], None],
        holdback: int,
    ) -> None:
        self._upstream = upstream
        self._scan = scan
        self._holdback = holdback

    def __iter__(self) -> Iterator[object]:
        buffer: list[object] = []
        text = ""
        tail = ""
        for chunk in self._upstream:
            buffer.append(chunk)
            text += _delta_text(chunk)
            if len(tail) + len(text) < self._holdback:
                continue
            scanned = tail + text
            self._scan(scanned)  # raises before releasing this window
            tail = _carry(scanned, self._holdback)
            text = ""
            yield from buffer
            buffer = []
        if buffer:
            self._scan(tail + text)  # exhaustion scan: cross-window straddle
            yield from buffer


class _AGuardedStream:
    """Async mirror of ``_GuardedStream`` via ``__aiter__``/``__anext__``.

    Same protocol and guarantees; the injected scan is awaited because sync
    guard methods are hostile to a running event loop (guard.py raises
    RuntimeError there).
    """

    def __init__(
        self,
        upstream: AsyncIterable[object],
        *,
        scan: Callable[[str], Awaitable[None]],
        holdback: int,
    ) -> None:
        self._upstream = upstream
        self._scan = scan
        self._holdback = holdback

    async def __aiter__(self) -> AsyncIterator[object]:
        buffer: list[object] = []
        text = ""
        tail = ""
        async for chunk in self._upstream:  # ponytail: SDK duck-type seam
            buffer.append(chunk)
            text += _delta_text(chunk)
            if len(tail) + len(text) < self._holdback:
                continue
            scanned = tail + text
            await self._scan(scanned)  # raises before releasing this window
            tail = _carry(scanned, self._holdback)
            text = ""
            for pending in buffer:  # yield from is illegal in async generators
                yield pending
            buffer = []
        if buffer:
            await self._scan(tail + text)  # exhaustion scan: cross-window straddle
            for pending in buffer:
                yield pending
