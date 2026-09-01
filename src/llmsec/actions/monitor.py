"""The host-side reference monitor: a deterministic authorization table.

``ReferenceMonitor.authorize`` is pure, synchronous, CPU-only. It consults only
host-declared configuration (the registry, the granted capabilities), the
untrusted proposal (:class:`~llmsec.actions.types.ToolCall`), the host-supplied
:class:`~llmsec.actions.types.Approval`, and the optional host-supplied findings
(a one-way tightening input, never an authority source). No detector, model,
network, or text-payload-approval read path exists on this route; approval is
never parsed out of ``call.arguments``.

Decision table (first match wins, deterministic order; plan todo 5):

0. Findings escalation, overlaid on the structural result below: a HIGH+ finding
   forces DENY (a structural DENY keeps its more specific reason); a MEDIUM
   finding floors ALLOW to REQUIRE_APPROVAL. Escalation never grants or widens.
1. Unknown tool -> DENY ``unregistered_tool``.
2. Schema mismatch -> DENY ``schema_violation``.
3. Capability: not granted + any write effect -> DENY ``missing_capability``;
   not granted + READ-only -> skip step 4 (bounded fail-open).
4. Approval (consulted only on capability-granted paths): required per the
   spec override or ``EFFECT_CONTROL``; missing -> REQUIRE_APPROVAL
   ``approval_required``; wrong digest -> DENY ``approval_mismatch``.
5. Tool listed in ``registry.inconsistencies`` -> REQUIRE_APPROVAL
   ``suspected_misdeclaration``.
6. Otherwise ALLOW ``authorized``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from llmsec.actions.enums import EFFECT_CONTROL, WRITE_EFFECTS, AuthorizationAction
from llmsec.actions.types import (
    Approval,
    AuthorizationDecision,
    Capability,
    ParamKind,
    ToolCall,
    ToolSpec,
    proposal_sha256,
)
from llmsec.core.enums import Severity, severity_rank
from llmsec.core.finding import Finding

if TYPE_CHECKING:
    from llmsec.actions.registry import ToolRegistry

#: Argument-type check per declared kind, as an exhaustive lookup table: a new
#: ``ParamKind`` member raises ``KeyError`` on first use instead of silently
#: accepting anything (the severity_rank / EFFECT_CONTROL tripwire idiom).
#: Exact ``type()`` matching, so ``bool`` never satisfies INT or FLOAT and an
#: ``int`` never satisfies FLOAT, regardless of Python's numeric tower.
_KIND_OK: dict[ParamKind, Callable[[object], bool]] = {
    ParamKind.STR: lambda value: type(value) is str,
    ParamKind.INT: lambda value: type(value) is int,
    ParamKind.FLOAT: lambda value: type(value) is float,
    ParamKind.BOOL: lambda value: type(value) is bool,
}

_HIGH_RANK = severity_rank(Severity.HIGH)
_MEDIUM_RANK = severity_rank(Severity.MEDIUM)


def _schema_ok(spec: ToolSpec, arguments: Mapping[str, object]) -> bool:
    """Structural validation of call arguments against the declared params."""
    declared = {param.name: param for param in spec.params}
    if not set(arguments) <= set(declared):
        return False
    for param in spec.params:
        if param.name not in arguments:
            if param.required:
                return False
            continue
        value = arguments[param.name]
        if not _KIND_OK[param.kind](value):
            return False
        if (
            param.kind is ParamKind.STR
            and isinstance(value, str)
            and len(value) > param.max_str_len
        ):
            return False
    return True


@dataclass(frozen=True, slots=True)
class ReferenceMonitor:
    """Authorize a proposed tool call against host-declared truth, deterministically.

    ``capabilities`` is the host-granted grant set for this (single, v1)
    principal; empty by default, which fail-closes every write effect and
    fail-opens only schema-valid READ calls.
    """

    registry: ToolRegistry
    capabilities: frozenset[Capability] = frozenset()

    def authorize(
        self,
        call: ToolCall,
        *,
        approval: Approval | None = None,
        findings: tuple[Finding, ...] = (),
    ) -> AuthorizationDecision:
        """Apply the decision table; every decision carries the call's digest."""
        started = time.perf_counter()
        digest = proposal_sha256(call)
        action, reason = self._structural(call, approval, digest)

        # Step 0: findings tighten the structural outcome, one way only.
        top_rank = max((severity_rank(finding.severity) for finding in findings), default=0)
        if top_rank >= _HIGH_RANK:
            if action is not AuthorizationAction.DENY:
                reason = "detection_escalated"
            action = AuthorizationAction.DENY
        elif top_rank == _MEDIUM_RANK and action is AuthorizationAction.ALLOW:
            action, reason = AuthorizationAction.REQUIRE_APPROVAL, "detection_escalated"

        return AuthorizationDecision(
            action=action,
            proposal_sha256=digest,
            reason=reason,
            findings=findings,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    def _structural(
        self, call: ToolCall, approval: Approval | None, digest: str
    ) -> tuple[AuthorizationAction, str]:
        """Decision-table steps 1-6; first match wins."""
        spec = self.registry.get(call.tool)
        if spec is None:
            return AuthorizationAction.DENY, "unregistered_tool"
        if not _schema_ok(spec, call.arguments):
            return AuthorizationAction.DENY, "schema_violation"

        granted = any(
            cap.tool == call.tool and cap.effects >= spec.effects for cap in self.capabilities
        )
        if granted:
            required = (
                spec.requires_approval
                if spec.requires_approval is not None
                else any(EFFECT_CONTROL[effect][0] for effect in spec.effects)
            )
            if required:
                if approval is None:
                    return AuthorizationAction.REQUIRE_APPROVAL, "approval_required"
                if approval.proposal_sha256 != digest:
                    return AuthorizationAction.DENY, "approval_mismatch"
        elif spec.effects & WRITE_EFFECTS:
            return AuthorizationAction.DENY, "missing_capability"
        # else: READ fail-open candidate; step 4 is never consulted without a grant.

        if call.tool in self.registry.inconsistencies:
            return AuthorizationAction.REQUIRE_APPROVAL, "suspected_misdeclaration"
        return AuthorizationAction.ALLOW, "authorized"
