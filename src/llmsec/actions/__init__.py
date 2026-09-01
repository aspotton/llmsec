"""Host-side reference monitor for proposed tool calls.

Exposes the typed vocabularies plus the tool spec/call/capability/approval and
authorization-decision types and the tool registry. The monitor itself
(todo 5) is re-exported here when it lands; until then importing that name
from this package raises ``ImportError``.
"""

from llmsec.actions.enums import (
    EFFECT_CONTROL,
    WRITE_EFFECTS,
    AuthorizationAction,
    EffectClass,
    ParamRole,
)
from llmsec.actions.registry import RegistryError, ToolRegistry, registry_from_dict
from llmsec.actions.types import (
    Approval,
    AuthorizationDecision,
    Capability,
    ParamKind,
    ToolCall,
    ToolParam,
    ToolSpec,
    proposal_sha256,
)

__all__ = [
    "EFFECT_CONTROL",
    "WRITE_EFFECTS",
    "Approval",
    "AuthorizationAction",
    "AuthorizationDecision",
    "Capability",
    "EffectClass",
    "ParamKind",
    "ParamRole",
    "RegistryError",
    "ToolCall",
    "ToolParam",
    "ToolRegistry",
    "ToolSpec",
    "proposal_sha256",
    "registry_from_dict",
]
