"""RED contract tests for the ``llmsec.actions`` public type surface.

These tests pin every public name and construction/validation rule locked by
``.omo/plans/roadmap-02-tool-action-security.md`` sections 4 (todo 2 + todo 3 code
blocks) and 5.1. They are written against an API that does not exist yet, so the
whole module fails to import (RED). House style: plain asserts with messages, no
fixtures or mocks (see tests/unit/test_policy.py).
"""

import pytest
from enum import Enum

from llmsec.actions import (
    EFFECT_CONTROL,
    WRITE_EFFECTS,
    Approval,
    AuthorizationAction,
    AuthorizationDecision,
    Capability,
    EffectClass,
    ParamKind,
    ParamRole,
    ToolCall,
    ToolParam,
    ToolSpec,
    proposal_sha256,
)


# --------------------------------------------------------------------------- #
# Helpers - a valid spec/call builder reused across the file.                  #
# --------------------------------------------------------------------------- #
def make_param(name: str, kind: ParamKind = ParamKind.STR) -> ToolParam:
    """Build a minimal valid ToolParam (generic role, required, default length)."""
    return ToolParam(name=name, kind=kind)


def make_spec(name: str = "reader", effects: frozenset[EffectClass] | None = None) -> ToolSpec:
    """Build a minimal valid ToolSpec with a single generic str param."""
    return ToolSpec(
        name=name,
        effects=effects if effects is not None else frozenset({EffectClass.READ}),
        params=(make_param("text"),),
    )


def make_call(tool: str = "reader", arguments: dict[str, object] | None = None) -> ToolCall:
    """Build a ToolCall for the named tool with the given (mutable) arguments."""
    return ToolCall(tool=tool, arguments=arguments if arguments is not None else {"text": "hi"})


# --------------------------------------------------------------------------- #
# Enum values (plan section 4, todo 2 code block).                             #
# --------------------------------------------------------------------------- #
def test_effect_class_values() -> None:
    assert EffectClass.READ == "read", EffectClass.READ
    assert EffectClass.EXTERNAL_WRITE == "external_write", EffectClass.EXTERNAL_WRITE
    assert EffectClass.DELETION == "deletion", EffectClass.DELETION
    assert EffectClass.DATA_EGRESS == "data_egress", EffectClass.DATA_EGRESS
    assert EffectClass.CODE_EXEC == "code_exec", EffectClass.CODE_EXEC
    assert EffectClass.FINANCIAL == "financial", EffectClass.FINANCIAL
    assert EffectClass.PERMISSION_CHANGE == "permission_change", EffectClass.PERMISSION_CHANGE
    assert EffectClass.MEMORY_PERSISTENCE == "memory_persistence", EffectClass.MEMORY_PERSISTENCE
    assert len(list(EffectClass)) == 8, "EffectClass must have exactly eight members"


def test_param_role_values() -> None:
    assert ParamRole.GENERIC == "generic", ParamRole.GENERIC
    assert ParamRole.DESTINATION == "destination", ParamRole.DESTINATION
    assert ParamRole.RESOURCE_SELECTOR == "resource_selector", ParamRole.RESOURCE_SELECTOR
    assert ParamRole.EXECUTABLE == "executable", ParamRole.EXECUTABLE
    assert ParamRole.FINANCIAL_VALUE == "financial_value", ParamRole.FINANCIAL_VALUE
    assert ParamRole.PAYLOAD == "payload", ParamRole.PAYLOAD


def test_param_kind_values() -> None:
    assert ParamKind.STR == "str", ParamKind.STR
    assert ParamKind.INT == "int", ParamKind.INT
    assert ParamKind.FLOAT == "float", ParamKind.FLOAT
    assert ParamKind.BOOL == "bool", ParamKind.BOOL


def test_authorization_action_values() -> None:
    assert AuthorizationAction.ALLOW == "allow", AuthorizationAction.ALLOW
    approval_value = AuthorizationAction.REQUIRE_APPROVAL
    assert approval_value == "require_approval", approval_value
    assert AuthorizationAction.DENY == "deny", AuthorizationAction.DENY
    assert len(list(AuthorizationAction)) == 3, "distinct vocabulary from DecisionAction"


def test_write_effects_is_every_effect_except_read() -> None:
    assert EffectClass.READ not in WRITE_EFFECTS, "READ is not a write effect"
    for effect in EffectClass:
        if effect is EffectClass.READ:
            continue
        assert effect in WRITE_EFFECTS, f"{effect} must be in WRITE_EFFECTS"


def test_effect_control_table() -> None:
    # (requires_approval, fail_closed)
    assert EFFECT_CONTROL[EffectClass.READ] == (False, False), EFFECT_CONTROL[EffectClass.READ]
    for effect in EffectClass:
        if effect is EffectClass.READ:
            continue
        assert EFFECT_CONTROL[effect] == (True, True), f"{effect} must require approval"


def test_effect_control_missing_member_raises_keyerror(monkeypatch: pytest.MonkeyPatch) -> None:
    # Tripwire idiom (mirrors severity_rank): a member with no table entry must
    # raise KeyError on first use rather than default permissive.
    monkeypatch.delitem(EFFECT_CONTROL, EffectClass.READ)
    with pytest.raises(KeyError):
        _ = EFFECT_CONTROL[EffectClass.READ]


@pytest.mark.parametrize(
    "enum_cls",
    [EffectClass, ParamKind, ParamRole, AuthorizationAction],
    ids=["effect", "kind", "role", "action"],
)
def test_unknown_enum_string_rejected(enum_cls: type[Enum]) -> None:
    with pytest.raises(ValueError):
        enum_cls("not_a_real_member")


# --------------------------------------------------------------------------- #
# ToolSpec validation.                                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_name",
    [
        "BadName",  # uppercase start
        "tool name with space",  # space is not allowed
        "tool\u200bname",  # zero-width space (U+200B) via explicit escape
        "1tool",  # must start with a lowercase letter
        "a" * 65,  # longer than the 64-char ceiling
    ],
    ids=["uppercase", "space", "zero_width", "digit_start", "too_long"],
)
def test_tool_spec_rejects_bad_name(bad_name: str) -> None:
    with pytest.raises(ValueError):
        ToolSpec(name=bad_name, effects=frozenset({EffectClass.READ}), params=(make_param("text"),))


def test_tool_spec_accepts_valid_name() -> None:
    spec = ToolSpec(
        name="tool.name-1_x",
        effects=frozenset({EffectClass.READ}),
        params=(make_param("text"),),
    )
    assert spec.name == "tool.name-1_x"


def test_tool_spec_rejects_duplicate_param_names() -> None:
    with pytest.raises(ValueError):
        ToolSpec(
            name="reader",
            effects=frozenset({EffectClass.READ}),
            params=(make_param("text"), make_param("text")),
        )


def test_tool_spec_rejects_more_than_64_params() -> None:
    params = tuple(make_param(f"p{i}") for i in range(65))
    with pytest.raises(ValueError):
        ToolSpec(name="reader", effects=frozenset({EffectClass.READ}), params=params)


def test_tool_spec_allows_64_params() -> None:
    params = tuple(make_param(f"p{i}") for i in range(64))
    spec = ToolSpec(name="reader", effects=frozenset({EffectClass.READ}), params=params)
    assert len(spec.params) == 64


# --------------------------------------------------------------------------- #
# Capability requires both fields.                                              #
# --------------------------------------------------------------------------- #
def test_capability_requires_tool() -> None:
    with pytest.raises(TypeError):
        Capability(effects=frozenset({EffectClass.READ}))


def test_capability_requires_effects() -> None:
    with pytest.raises(TypeError):
        Capability(tool="reader")


# --------------------------------------------------------------------------- #
# Approval digest validation.                                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_digest",
    ["not-hex", "0" * 63, "0" * 65, "deadbeef" * 8 + "z"],
    ids=["non_hex", "too_short", "too_long", "trailing_non_hex"],
)
def test_approval_rejects_malformed_digest(bad_digest: str) -> None:
    with pytest.raises(ValueError):
        Approval(proposal_sha256=bad_digest, approver="host")


def test_approval_accepts_64_hex_digest() -> None:
    approval = Approval(proposal_sha256="0123456789abcdef" * 4, approver="host")
    assert approval.approver == "host"


# --------------------------------------------------------------------------- #
# proposal_sha256 stability.                                                    #
# --------------------------------------------------------------------------- #
def test_proposal_sha256_is_key_order_independent() -> None:
    call_a = ToolCall(tool="reader", arguments={"a": 1, "b": 2})
    call_b = ToolCall(tool="reader", arguments={"b": 2, "a": 1})
    assert proposal_sha256(call_a) == proposal_sha256(call_b)


def test_proposal_sha256_immune_to_source_dict_mutation() -> None:
    # The snapshot (MappingProxyType) must freeze the validated view: mutating the
    # caller's source dict after construction must NOT change the digest.
    source = {"a": 1, "b": 2}
    call = ToolCall(tool="reader", arguments=source)
    before = proposal_sha256(call)
    source["a"] = 999
    source["c"] = "injected"
    after = proposal_sha256(call)
    assert before == after, "post-construction source mutation must not change the digest"


# --------------------------------------------------------------------------- #
# AuthorizationDecision.commit_allowed / denied.                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("action", "expected_commit"),
    [
        (AuthorizationAction.ALLOW, True),
        (AuthorizationAction.REQUIRE_APPROVAL, False),
        (AuthorizationAction.DENY, False),
    ],
)
def test_commit_allowed_matches_allow_only(
    action: AuthorizationAction, expected_commit: bool
) -> None:
    decision = AuthorizationDecision(
        action=action,
        proposal_sha256="0123456789abcdef" * 4,
        reason="authorized",
    )
    assert decision.commit_allowed is expected_commit, (action, decision.commit_allowed)


def test_denied_true_only_for_deny() -> None:
    for action, expected in (
        (AuthorizationAction.DENY, True),
        (AuthorizationAction.ALLOW, False),
        (AuthorizationAction.REQUIRE_APPROVAL, False),
    ):
        decision = AuthorizationDecision(
            action=action,
            proposal_sha256="0123456789abcdef" * 4,
            reason="x",
        )
        assert decision.denied is expected, (action, decision.denied)
