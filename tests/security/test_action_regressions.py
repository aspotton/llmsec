"""Security lock-ins for the tool/action reference monitor (plan 5.2).

These seven regressions encode the non-negotiable security guarantees of roadmap
02. Each is one narrative scenario, asserted with a message (house style). The
public API does not exist yet, so this module fails to import (RED).
"""

import pytest

from llmsec import Finding, Guard, Severity
from llmsec.actions import (
    Approval,
    AuthorizationAction,
    Capability,
    EffectClass,
    ParamKind,
    ParamRole,
    ToolCall,
    proposal_sha256,
    registry_from_dict,
)

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------- #
# Helper factories.                                                            #
# --------------------------------------------------------------------------- #
def _param(
    name: str,
    kind: ParamKind = ParamKind.STR,
    role: ParamRole = ParamRole.GENERIC,
) -> dict[str, object]:
    return {"name": name, "kind": kind.value, "role": role.value, "required": True}


def make_registry() -> object:
    return registry_from_dict(
        {
            "tools": [
                {
                    "name": "egress",
                    "effects": [EffectClass.DATA_EGRESS.value],
                    "params": [_param("payload", role=ParamRole.PAYLOAD)],
                },
                {
                    "name": "reader",
                    "effects": [EffectClass.READ.value],
                    "params": [_param("value")],
                },
            ]
        }
    )


def make_monitor(capabilities: frozenset[Capability] = frozenset()) -> object:
    from llmsec.actions import ReferenceMonitor

    return ReferenceMonitor(registry=make_registry(), capabilities=capabilities)


def _finding(severity: Severity) -> tuple[Finding, ...]:
    finding = Finding(
        detector="test",
        category="attack",
        confidence=0.99,
        severity=severity,
        message="x",
    )
    return (finding,)


# --------------------------------------------------------------------------- #
# 1. Detection success never grants a capability (no detector argument exists). #
# --------------------------------------------------------------------------- #
def test_detector_allow_never_grants_capability() -> None:
    call = ToolCall(tool="egress", arguments={"payload": "data"})
    granted = frozenset({Capability(tool="egress", effects=frozenset({EffectClass.DATA_EGRESS}))})

    allowed = make_monitor(capabilities=granted).authorize(call, approval=None, findings=())
    # write effect still needs approval, so a granted write with no approval is
    # REQUIRE_APPROVAL - never ALLOW via detection. The capability check passed.
    assert allowed.action is AuthorizationAction.REQUIRE_APPROVAL, allowed.reason

    denied = make_monitor(capabilities=frozenset()).authorize(call, approval=None, findings=())
    assert denied.action is AuthorizationAction.DENY
    assert denied.reason == "missing_capability", denied.reason


# --------------------------------------------------------------------------- #
# 2. Findings only ever tighten, never grant, and never satisfy approval.       #
# --------------------------------------------------------------------------- #
def test_findings_escalate_never_grant() -> None:
    # (a) write tool, capability granted, valid approval: HIGH input -> DENY,
    #     zero findings -> the same call proceeds (ALLOW). One-way direction.
    effect = EffectClass.DATA_EGRESS
    call = ToolCall(tool="egress", arguments={"payload": "data"})
    granted = frozenset({Capability(tool="egress", effects=frozenset({effect}))})
    monitor = make_monitor(capabilities=granted)
    approval = Approval(proposal_sha256=proposal_sha256(call), approver="host")

    high = monitor.authorize(call, approval=approval, findings=_finding(Severity.HIGH))
    assert high.action is AuthorizationAction.DENY
    assert high.reason == "detection_escalated", high.reason

    clean = monitor.authorize(call, approval=approval, findings=())
    assert clean.action is AuthorizationAction.ALLOW, clean.reason

    # (b) fail-open tightening: READ-only, NO capability (would ALLOW via
    #     fail-open), MEDIUM input -> REQUIRE_APPROVAL, never ALLOW.
    read_call = ToolCall(tool="reader", arguments={"value": "x"})
    findings = _finding(Severity.MEDIUM)
    escalated = make_monitor().authorize(read_call, approval=None, findings=findings)
    assert escalated.action is AuthorizationAction.REQUIRE_APPROVAL, escalated.reason


# --------------------------------------------------------------------------- #
# 3. Model-claimed approval inside the payload is inert; digest is authoritative.#
# --------------------------------------------------------------------------- #
def test_model_claimed_approval_is_not_approval() -> None:
    effect = EffectClass.DATA_EGRESS
    granted = frozenset({Capability(tool="egress", effects=frozenset({effect}))})
    # Call A carries "approval" fields inside its untrusted payload; no Approval arg.
    claim = ToolCall(
        tool="egress",
        arguments={"payload": "data", "approved": True, "proposal_sha256": "0123456789abcdef" * 4},
    )
    decision = make_monitor(capabilities=granted).authorize(claim, approval=None)
    assert decision.action is AuthorizationAction.REQUIRE_APPROVAL, decision.reason
    assert decision.reason == "approval_required", decision.reason

    # An Approval bound to call A, replayed against a different call B, must DENY.
    call_a = ToolCall(tool="egress", arguments={"payload": "a"})
    call_b = ToolCall(tool="egress", arguments={"payload": "b"})
    approval_a = Approval(proposal_sha256=proposal_sha256(call_a), approver="host")
    replay = make_monitor(capabilities=granted).authorize(call_b, approval=approval_a)
    assert replay.action is AuthorizationAction.DENY
    assert replay.reason == "approval_mismatch", replay.reason


# --------------------------------------------------------------------------- #
# 4. Unregistered tools are denied.                                            #
# --------------------------------------------------------------------------- #
def test_unregistered_tool_denied() -> None:
    decision = make_monitor().authorize(ToolCall(tool="ghost", arguments={"value": "x"}))
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "unregistered_tool", decision.reason


# --------------------------------------------------------------------------- #
# 5. Schema mismatch is denied.                                                #
# --------------------------------------------------------------------------- #
def test_schema_mismatch_denied() -> None:
    # wrong kind: str payload supplied where the tool expects its own typed shape.
    wrong_kind = make_monitor().authorize(ToolCall(tool="reader", arguments={"value": 12345}))
    assert wrong_kind.action is AuthorizationAction.DENY
    assert wrong_kind.reason == "schema_violation", wrong_kind.reason

    # oversize PAYLOAD string
    big = ToolCall(tool="egress", arguments={"payload": "x" * 200_000})
    oversize = make_monitor().authorize(big)
    assert oversize.action is AuthorizationAction.DENY
    assert oversize.reason == "schema_violation", oversize.reason


# --------------------------------------------------------------------------- #
# 6. READ fail-open is bounded to a valid schema.                              #
# --------------------------------------------------------------------------- #
def test_read_fail_open_is_bounded() -> None:
    # reader declares READ-only with GENERIC-only params (no non-GENERIC role),
    # so the mis-declaration heuristic (step 5) does not fire.
    ok = make_monitor().authorize(ToolCall(tool="reader", arguments={"value": "x"}))
    assert ok.action is AuthorizationAction.ALLOW, ok.reason

    extra = ToolCall(tool="reader", arguments={"value": "x", "extra": 1})
    unknown_param = make_monitor().authorize(extra)
    assert unknown_param.action is AuthorizationAction.DENY
    assert unknown_param.reason == "schema_violation", unknown_param.reason


# --------------------------------------------------------------------------- #
# 7. An unconfigured Guard denies by default.                                  #
# --------------------------------------------------------------------------- #
def test_unconfigured_guard_denies_by_default() -> None:
    call = ToolCall(tool="reader", arguments={"value": "x"})
    decision = Guard.default().authorize_tool_call(call)
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "no_monitor", decision.reason
    assert decision.commit_allowed is False
