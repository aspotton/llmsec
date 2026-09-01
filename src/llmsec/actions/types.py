"""Tool specification, call, capability, approval and authorization types.

These are the value types the reference monitor (todo 5) decides over. Two
invariants hold them together:

* Nothing here is derived from model-produced text. Effects, capabilities and
  approvals are host-supplied; :class:`ToolCall` is the untrusted proposal.
* :class:`ToolCall` snapshots its arguments on construction, so the digest the
  host shows a human and the digest the monitor later re-derives describe the
  same call even if the caller mutates its own dictionary afterwards.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from llmsec.actions.enums import AuthorizationAction, EffectClass, ParamRole
from llmsec.core.finding import Finding

_TOOL_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_.\-]{0,63}$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")

#: Ceiling on the number of parameters a single tool may declare.
MAX_PARAMS: Final = 64


class ParamKind(StrEnum):
    """JSON-native scalar type a tool parameter accepts.

    The monitor checks an argument against the declared kind structurally;
    ``BOOL`` is not interchangeable with ``INT`` even though Python treats
    ``True`` as ``1``, because a flag is not a count.
    """

    STR = "str"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"


@dataclass(frozen=True, slots=True)
class ToolParam:
    """One declared parameter of a tool."""

    name: str
    kind: ParamKind
    role: ParamRole = ParamRole.GENERIC
    required: bool = True
    max_str_len: int = 8192  # bound applied to PAYLOAD-role string values


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Host-declared shape and blast radius of a tool."""

    name: str
    effects: frozenset[EffectClass]
    params: tuple[ToolParam, ...]
    requires_approval: bool | None = None  # None => EFFECT_CONTROL default

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError(
                "tool name must match ^[a-z][a-z0-9_.-]{0,63}$ "
                "(lowercase, no whitespace, no invisible characters)"
            )
        if len(self.params) > MAX_PARAMS:
            raise ValueError(f"too many params: max {MAX_PARAMS}, got {len(self.params)}")
        seen: set[str] = set()
        for param in self.params:
            if param.name in seen:
                raise ValueError(f"tool {self.name!r} declares duplicate param {param.name!r}")
            seen.add(param.name)


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A proposed tool invocation: the thing a human approves and a host commits."""

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # TOCTOU defense, inside-process: take our own copy behind a read-only
        # view so that mutating the caller's dict later cannot silently change
        # what proposal_sha256(call) commits to.
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True, slots=True)
class Capability:
    """A tool plus the effects the host has granted this agent to trigger.

    Host-granted authority only; never inferred from model output.
    """

    tool: str
    effects: frozenset[EffectClass]

    def __post_init__(self) -> None:
        if not self.tool:
            raise ValueError("capability tool must be a non-empty string")


@dataclass(frozen=True, slots=True)
class Approval:
    """A human's yes, bound to the digest of one exact call."""

    proposal_sha256: str
    approver: str

    def __post_init__(self) -> None:
        if not _HEX64_RE.fullmatch(self.proposal_sha256):
            raise ValueError("approval proposal_sha256 must be 64 lowercase hex characters")


def _canonical(value: object) -> dict[str, str]:
    """Stand-in for a value ``json`` cannot encode.

    For JSON-native arguments the digest is the portable section 5.3 form. For
    exotic values this repr form is an llmsec-internal digest only: stable
    within one process for a given logical call, not claimed stable across
    processes or implementations.
    """
    return {"__llmsec_repr__": repr(value)}


def _canonical_json(payload: Mapping[str, object]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_canonical,
    )


def proposal_sha256(call: ToolCall) -> str:
    """Hex digest of the exact call a host must commit for an approval to hold."""
    payload: dict[str, object] = {"tool": call.tool, "arguments": dict(call.arguments)}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Outcome of the commit gate.

    Deliberately not a ``Decision``: committing an action and admitting content
    are different questions (principle 12).
    """

    action: AuthorizationAction
    proposal_sha256: str
    reason: str
    findings: tuple[Finding, ...] = ()
    elapsed_ms: float = 0.0

    @property
    def commit_allowed(self) -> bool:
        return self.action is AuthorizationAction.ALLOW

    @property
    def denied(self) -> bool:
        return self.action is AuthorizationAction.DENY
