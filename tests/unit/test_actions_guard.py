"""``Guard.authorize_tool_call`` facade: deny-by-default and monitor passthrough.

Pins the todo-6 contract: with no monitor the facade never raises and never
allows (DENY ``no_monitor``); with a monitor it is the monitor's decision,
unchanged; and the legacy positional ``Guard(detectors, policy, diagnostics)``
construction must keep working with the monitor field appended last. Plain
asserts with messages, no fixtures/mocks (house style).
"""

from llmsec import (
    Approval,
    AuthorizationAction,
    AuthorizationDecision,
    Capability,
    EffectClass,
    Finding,
    Guard,
    ParamKind,
    ParamRole,
    ReferenceMonitor,
    Severity,
    ToolCall,
    ToolParam,
    ToolRegistry,
    ToolSpec,
)
from llmsec.actions import proposal_sha256
from llmsec.policy import DefaultPolicy


def make_monitor() -> ReferenceMonitor:
    """Read-only registered tool, capability granted: monitor says ALLOW."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="fs.read",
            effects=frozenset({EffectClass.READ}),
            params=(ToolParam(name="path", kind=ParamKind.STR, role=ParamRole.GENERIC),),
        )
    )
    return ReferenceMonitor(
        registry,
        frozenset({Capability(tool="fs.read", effects=frozenset({EffectClass.READ}))}),
    )


def make_call() -> ToolCall:
    return ToolCall(tool="fs.read", arguments={"path": "/etc/hosts"})


def test_guard_without_monitor_denies_by_default() -> None:
    """Given: a Guard with no monitor. When: authorizing any call. Then: DENY no_monitor."""
    guard = Guard(detectors=[], policy=DefaultPolicy())
    call = make_call()
    decision = guard.authorize_tool_call(call)
    assert isinstance(decision, AuthorizationDecision), "facade returns the commit-gate type"
    assert decision.action is AuthorizationAction.DENY, "no monitor must never allow"
    assert decision.reason == "no_monitor", f"reason was {decision.reason!r}"
    assert decision.commit_allowed is False, "deny must never be commit-allowed"
    assert decision.proposal_sha256 == proposal_sha256(call), "digest must still bind the call"


def test_guard_without_monitor_never_raises_on_garbage_arguments() -> None:
    """Given: no monitor and exotic argument values. When: authorizing. Then: DENY, no raise."""
    guard = Guard(detectors=[], policy=DefaultPolicy())
    garbage = ToolCall(
        tool="<|system|>",
        arguments={"weird": object(), "nested": [{"k": (1, 2)}], "n": float("nan")},
    )
    decision = guard.authorize_tool_call(garbage)
    assert decision.action is AuthorizationAction.DENY, "garbage input must still deny"
    assert decision.reason == "no_monitor", f"reason was {decision.reason!r}"


def test_guard_monitor_passthrough_matches_monitor_authorize() -> None:
    """Given: a configured monitor. When: facade authorize. Then: the monitor's decision."""
    monitor = make_monitor()
    guard = Guard(detectors=[], policy=DefaultPolicy(), monitor=monitor)
    call = make_call()
    facade = guard.authorize_tool_call(call)
    direct = monitor.authorize(call)
    assert facade.action is direct.action, "facade must not alter the action"
    assert facade.reason == direct.reason, "facade must not alter the reason"
    assert facade.proposal_sha256 == direct.proposal_sha256, "digest must pass through"


def test_guard_monitor_passthrough_carries_approval_and_findings() -> None:
    """Given: a monitor + approval + finding. When: facade authorize. Then: monitor's DENY."""
    monitor = make_monitor()
    guard = Guard(detectors=[], policy=DefaultPolicy(), monitor=monitor)
    call = make_call()
    wrong_approval = Approval(proposal_sha256="0" * 64, approver="mallory")
    finding = Finding(
        detector="stub",
        category="injection",
        confidence=0.9,
        severity=Severity.HIGH,
        message="pinned",
    )
    decision = guard.authorize_tool_call(call, approval=wrong_approval, findings=(finding,))
    assert decision.action is AuthorizationAction.DENY, "monitor verdict must pass"
    assert decision.reason == "detection_escalated", f"reason was {decision.reason!r}"
    assert decision.findings == (finding,), "input findings must be carried, not computed"


def test_guard_positional_legacy_construction_still_works() -> None:
    """Given: the pre-actions positional signature. When: constructing + authorizing. Then: DENY."""
    guard = Guard([], DefaultPolicy(), False)
    decision = guard.authorize_tool_call(make_call())
    assert decision.action is AuthorizationAction.DENY, "legacy Guard has no monitor"
    assert decision.reason == "no_monitor", f"reason was {decision.reason!r}"


def test_guard_default_denies_by_default() -> None:
    """Given: Guard.default(). When: authorize_tool_call. Then: DENY, no auto-monitor."""
    decision = Guard.default().authorize_tool_call(make_call())
    assert decision.action is AuthorizationAction.DENY, "default Guard must not build a monitor"
    assert decision.reason == "no_monitor", f"reason was {decision.reason!r}"
