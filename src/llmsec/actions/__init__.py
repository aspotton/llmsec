"""Host-side reference monitor for proposed tool calls.

Exposes the typed vocabularies plus the tool spec/call/capability/approval and
authorization-decision types, the tool registry, and the reference monitor
itself (``ReferenceMonitor``).
"""

from llmsec.actions.enums import (
    EFFECT_CONTROL,
    WRITE_EFFECTS,
    AuthorizationAction,
    EffectClass,
    ParamRole,
)
from llmsec.actions.monitor import ReferenceMonitor
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
    "ReferenceMonitor",
    "RegistryError",
    "ToolCall",
    "ToolParam",
    "ToolRegistry",
    "ToolSpec",
    "proposal_sha256",
    "registry_from_dict",
]
