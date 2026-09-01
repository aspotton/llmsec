"""RED contract tests for ``ReferenceMonitor.authorize`` (todo-5 decision table).

One test per row of the todo-5 decision table (steps 0-6), plus the interaction
rows called out in plan section 4 todo 1. These pin the exact
``AuthorizationAction`` and the machine ``reason`` category for each row. The API
does not exist yet, so the module fails to import (RED). Plain asserts with
messages, no fixtures/mocks (house style).
"""

import pytest

from llmsec import Finding, Severity
from llmsec.actions import (
    AuthorizationAction,
    Capability,
    EffectClass,
    ParamKind,
    ParamRole,
    ToolCall,
    registry_from_dict,
)

# --------------------------------------------------------------------------- #
# Helper factories (functions from the 5.1 surface).                            #
# --------------------------------------------------------------------------- #
# A registered tool per write effect, each with one required generic str param,
# so row (e) can exercise every write effect on identical structure.
WRITE_TOOLS: dict[EffectClass, str] = {
    EffectClass.EXTERNAL_WRITE: "w_external_write",
    EffectClass.DELETION: "w_deletion",
    EffectClass.DATA_EGRESS: "w_data_egress",
    EffectClass.CODE_EXEC: "w_code_exec",
    EffectClass.FINANCIAL: "w_financial",
    EffectClass.PERMISSION_CHANGE: "w_permission_change",
    EffectClass.MEMORY_PERSISTENCE: "w_memory_persistence",
}

WRITE_ARGS = {effect: {"value": "x"} for effect in WRITE_TOOLS}


def _param(
    name: str,
    kind: ParamKind = ParamKind.STR,
    role: ParamRole = ParamRole.GENERIC,
    **extra: object,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": name,
        "kind": kind.value,
        "role": role.value,
        "required": True,
    }
    entry.update(extra)
    return entry


def make_registry() -> object:
    tools: list[dict[str, object]] = [
        # READ-known tool (fail-open candidate, valid schema).
        {"name": "reader", "effects": ["read"], "params": [_param("value")]},
        # READ-only tool that also carries a non-GENERIC role param -> registry
        # inconsistency (suspected_misdeclaration), row (h).
        {
            "name": "misdeclared",
            "effects": ["read"],
            "params": [_param("value"), _param("dest", role=ParamRole.DESTINATION)],
        },
        # Typed-kind tools for schema mismatch, row (b).
        {
            "name": "calc",
            "effects": ["read"],
            "params": [
                _param("amount", kind=ParamKind.FLOAT),
                _param("count", kind=ParamKind.INT),
                _param("flag", kind=ParamKind.BOOL),
            ],
        },
        # Short-length tool for over-max_str_len, row (b).
        {"name": "shorty", "effects": ["read"], "params": [_param("value", max_str_len=8)]},
    ]
    for effect, name in WRITE_TOOLS.items():
        tools.append({"name": name, "effects": [effect.value], "params": [_param("value")]})
    return registry_from_dict({"tools": tools})


def make_monitor(capabilities: frozenset[Capability] = frozenset()) -> object:
    from llmsec.actions import ReferenceMonitor

    return ReferenceMonitor(registry=make_registry(), capabilities=capabilities)


def granted(tool: str, *effects: EffectClass) -> frozenset[Capability]:
    return frozenset({Capability(tool=tool, effects=frozenset(effects))})


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
# (a) Row 1: unknown tool -> DENY unregistered_tool.                            #
# --------------------------------------------------------------------------- #
def test_unknown_tool_denied() -> None:
    decision = make_monitor().authorize(ToolCall(tool="ghost", arguments={"value": "x"}))
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "unregistered_tool", decision.reason


# --------------------------------------------------------------------------- #
# (b) Row 2: schema mismatch variants -> DENY schema_violation.                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        pytest.param("calc", {"amount": 5, "count": 1, "flag": True}, id="int_where_float"),
        pytest.param("calc", {"amount": 1.0, "count": True, "flag": True}, id="bool_where_int"),
        pytest.param("reader", {"count": 1, "flag": True}, id="missing_required"),
        pytest.param("reader", {"value": "x", "extra": 1}, id="unknown_param"),
        pytest.param("shorty", {"value": "x" * 9}, id="over_max_str_len"),
    ],
)
def test_schema_mismatch_denied(tool: str, arguments: dict[str, object]) -> None:
    decision = make_monitor().authorize(ToolCall(tool=tool, arguments=arguments))
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "schema_violation", decision.reason


# --------------------------------------------------------------------------- #
# (c) Row 3: write effect, no capability -> DENY missing_capability.            #
# --------------------------------------------------------------------------- #
def test_write_without_capability_denied() -> None:
    effect = EffectClass.DATA_EGRESS
    call = ToolCall(tool=WRITE_TOOLS[effect], arguments=WRITE_ARGS[effect])
    decision = make_monitor().authorize(call)
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "missing_capability", decision.reason


# --------------------------------------------------------------------------- #
# (d) Row 3/6: READ known+valid, no capability -> ALLOW (fail-open).            #
# --------------------------------------------------------------------------- #
def test_read_fail_open_allows() -> None:
    decision = make_monitor().authorize(ToolCall(tool="reader", arguments={"value": "x"}))
    assert decision.action is AuthorizationAction.ALLOW
    assert decision.commit_allowed is True


# --------------------------------------------------------------------------- #
# (e) Row 4: write, capability granted, approval=None -> REQUIRE_APPROVAL, for  #
#     ALL SEVEN write effects.                                                  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("effect", list(WRITE_TOOLS.keys()), ids=[e.value for e in WRITE_TOOLS])
def test_write_granted_without_approval_requires_approval(effect: EffectClass) -> None:
    tool = WRITE_TOOLS[effect]
    monitor = make_monitor(capabilities=granted(tool, effect))
    decision = monitor.authorize(ToolCall(tool=tool, arguments=WRITE_ARGS[effect]), approval=None)
    assert decision.action is AuthorizationAction.REQUIRE_APPROVAL
    assert decision.reason == "approval_required", decision.reason


# --------------------------------------------------------------------------- #
# (f) Row 4/6: valid Approval with matching digest -> ALLOW.                    #
# --------------------------------------------------------------------------- #
def test_write_granted_with_matching_approval_allows() -> None:
    from llmsec.actions import Approval, proposal_sha256

    effect = EffectClass.EXTERNAL_WRITE
    tool = WRITE_TOOLS[effect]
    call = ToolCall(tool=tool, arguments=WRITE_ARGS[effect])
    monitor = make_monitor(capabilities=granted(tool, effect))
    approval = Approval(proposal_sha256=proposal_sha256(call), approver="host")
    decision = monitor.authorize(call, approval=approval)
    assert decision.action is AuthorizationAction.ALLOW
    assert decision.commit_allowed is True


# --------------------------------------------------------------------------- #
# (g) Row 4: Approval digest for a DIFFERENT call -> DENY approval_mismatch.    #
# --------------------------------------------------------------------------- #
def test_approval_digest_for_other_call_denied() -> None:
    from llmsec.actions import Approval, proposal_sha256

    effect = EffectClass.EXTERNAL_WRITE
    tool = WRITE_TOOLS[effect]
    call = ToolCall(tool=tool, arguments=WRITE_ARGS[effect])
    other = ToolCall(tool=tool, arguments={"value": "different"})
    monitor = make_monitor(capabilities=granted(tool, effect))
    approval = Approval(proposal_sha256=proposal_sha256(other), approver="host")
    decision = monitor.authorize(call, approval=approval)
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "approval_mismatch", decision.reason


# --------------------------------------------------------------------------- #
# (h) Row 5: tool in registry.inconsistencies -> REQUIRE_APPROVAL               #
#     suspected_misdeclaration.                                                 #
# --------------------------------------------------------------------------- #
def test_suspected_misdeclaration_requires_approval() -> None:
    registry = make_registry()
    assert "misdeclared" in registry.inconsistencies, registry.inconsistencies
    monitor = make_monitor()
    call = ToolCall(tool="misdeclared", arguments={"value": "x", "dest": "d"})
    decision = monitor.authorize(call)
    assert decision.action is AuthorizationAction.REQUIRE_APPROVAL
    assert decision.reason == "suspected_misdeclaration", decision.reason


# --------------------------------------------------------------------------- #
# (i) Row 0: HIGH finding on registered+granted+approved -> DENY                #
#     detection_escalated.                                                      #
# --------------------------------------------------------------------------- #
def test_high_finding_escalates_to_deny() -> None:
    from llmsec.actions import Approval, proposal_sha256

    effect = EffectClass.EXTERNAL_WRITE
    tool = WRITE_TOOLS[effect]
    call = ToolCall(tool=tool, arguments=WRITE_ARGS[effect])
    monitor = make_monitor(capabilities=granted(tool, effect))
    decision = monitor.authorize(
        call,
        approval=Approval(proposal_sha256=proposal_sha256(call), approver="host"),
        findings=_finding(Severity.HIGH),
    )
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "detection_escalated", decision.reason


# --------------------------------------------------------------------------- #
# (j) Row 0/3: MEDIUM finding on a READ fail-open call -> REQUIRE_APPROVAL.     #
# --------------------------------------------------------------------------- #
def test_medium_finding_on_read_fail_open_requires_approval() -> None:
    decision = make_monitor().authorize(
        ToolCall(tool="reader", arguments={"value": "x"}), findings=_finding(Severity.MEDIUM)
    )
    assert decision.action is AuthorizationAction.REQUIRE_APPROVAL, decision.action


# --------------------------------------------------------------------------- #
# (k) Row 0 vs 1: escalation never downgrades - HIGH + unregistered still DENY. #
#     Structural DENY (step 1) wins over the escalation label.                  #
# --------------------------------------------------------------------------- #
def test_escalation_never_downgrades_structural_deny() -> None:
    decision = make_monitor().authorize(
        ToolCall(tool="ghost", arguments={"value": "x"}), findings=_finding(Severity.HIGH)
    )
    assert decision.action is AuthorizationAction.DENY
    assert decision.reason == "unregistered_tool", decision.reason
