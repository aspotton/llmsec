"""Typed effect, parameter-role, and authorization vocabularies.

Free-form strings are forbidden for security metadata (repository invariant:
"do not introduce free-form string identifiers for ... decisions"). Every
member here is an explicit ``StrEnum`` so the wire value stays stable while the
Python name stays checkable.
"""

from enum import StrEnum
from typing import Final


class EffectClass(StrEnum):
    """Host-declared category of what a tool call can change.

    Effects are declared by the host in the tool registry, never inferred from
    model-produced text.
    """

    READ = "read"
    EXTERNAL_WRITE = "external_write"
    DELETION = "deletion"
    DATA_EGRESS = "data_egress"
    CODE_EXEC = "code_exec"
    FINANCIAL = "financial"
    PERMISSION_CHANGE = "permission_change"
    MEMORY_PERSISTENCE = "memory_persistence"


WRITE_EFFECTS: Final[frozenset[EffectClass]] = frozenset(EffectClass) - {EffectClass.READ}

# Exhaustive dict, severity_rank tripwire idiom: a new EffectClass member with no
# entry raises KeyError on first use rather than defaulting permissive.
EFFECT_CONTROL: Final[dict[EffectClass, tuple[bool, bool]]] = {
    # (requires_approval, fail_closed)
    EffectClass.READ: (False, False),
    EffectClass.EXTERNAL_WRITE: (True, True),
    EffectClass.DELETION: (True, True),
    EffectClass.DATA_EGRESS: (True, True),
    EffectClass.CODE_EXEC: (True, True),
    EffectClass.FINANCIAL: (True, True),
    EffectClass.PERMISSION_CHANGE: (True, True),
    EffectClass.MEMORY_PERSISTENCE: (True, True),
}


class ParamRole(StrEnum):
    """What a tool parameter means, so the monitor can spot mis-declaration.

    A ``GENERIC`` role carries no structural risk signal; the other roles mark
    parameters whose values decide where data goes, what runs, or how much is
    spent.
    """

    GENERIC = "generic"
    DESTINATION = "destination"
    RESOURCE_SELECTOR = "resource_selector"
    EXECUTABLE = "executable"
    FINANCIAL_VALUE = "financial_value"
    PAYLOAD = "payload"


class AuthorizationAction(StrEnum):
    """Commit-gate outcome for a proposed tool call.

    Deliberately distinct from ``DecisionAction``: content decisions have
    SANITIZE/QUARANTINE/etc., whereas committing an action has exactly three
    states (principle 12, distinct concepts stay distinct).
    """

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"
