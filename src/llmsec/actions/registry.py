"""Host-declared tool registry plus a schema-checked JSON loader.

The registry is host configuration, i.e. trusted input; model output only ever
reaches the monitor through :class:`~llmsec.actions.types.ToolCall`. The loader
parses the wire shape into typed :class:`~llmsec.actions.types.ToolSpec`
values and rejects every schema violation at once, so a raw ``str`` can never
masquerade as an effect, kind, or role (repository invariant: no free-form
string identifiers for security metadata).

The registry also records one self-consistency warning per tool: a tool that
declares READ-only effects yet carries a non-``GENERIC`` role param is a
likely mis-declaration. ``inconsistencies`` is a heuristic surfaced by the
monitor as ``suspected_misdeclaration``, never an authority; a host that
uniformly mis-declares a tool's effects cannot be detected from the
declaration alone, and is documented as a limitation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, TypeVar

from llmsec.actions.enums import EffectClass, ParamRole
from llmsec.actions.types import ParamKind, ToolParam, ToolSpec

_READ_ONLY: Final = frozenset({EffectClass.READ})

_StrEnumT = TypeVar("_StrEnumT", bound=EffectClass | ParamKind | ParamRole)


class RegistryError(Exception):
    """A tool name was registered twice."""


class ToolRegistry:
    """The host's declared tools, keyed by name."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._inconsistent: list[str] = []

    @classmethod
    def from_json(cls, path: str | Path) -> ToolRegistry:
        """Load a registry from a JSON file path (thin stdlib-json wrapper)."""
        return registry_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def register(self, spec: ToolSpec) -> None:
        """Add one declared tool. Duplicate names raise :class:`RegistryError`."""
        if spec.name in self._specs:
            raise RegistryError(f"tool {spec.name!r} is already registered")
        self._specs[spec.name] = spec
        if spec.effects == _READ_ONLY and any(p.role is not ParamRole.GENERIC for p in spec.params):
            self._inconsistent.append(spec.name)

    def get(self, name: str) -> ToolSpec | None:
        """The spec registered under ``name``, or None when unknown."""
        return self._specs.get(name)

    @property
    def inconsistencies(self) -> tuple[str, ...]:
        """Names of READ-declared tools carrying a non-GENERIC role param.

        A warning surface for the monitor (step 5), not an authority.
        """
        return tuple(self._inconsistent)

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, name: object) -> bool:
        return name in self._specs


def _member(
    raw: object, enum_cls: type[_StrEnumT], where: str, violations: list[str]
) -> _StrEnumT | None:
    """Parse a wire string into an enum member; never pass raw strings through."""
    if not isinstance(raw, str):
        violations.append(f"{where}: {raw!r} is not a valid {enum_cls.__name__}")
        return None
    try:
        return enum_cls(raw)
    except ValueError:
        violations.append(f"{where}: {raw!r} is not a valid {enum_cls.__name__}")
        return None


def _parse_param(entry: object, where: str, violations: list[str]) -> ToolParam | None:
    """Parse one declared param, recording every violation instead of failing fast."""
    if not isinstance(entry, dict):
        violations.append(f"{where}: param must be a JSON object")
        return None
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        violations.append(f"{where}: param name must be a non-empty string")
        return None
    param_where = f"{where}.{name}"
    kind = _member(entry.get("kind"), ParamKind, f"{param_where} kind", violations)
    role = _member(
        entry.get("role", ParamRole.GENERIC), ParamRole, f"{param_where} role", violations
    )
    required = entry.get("required", True)
    if not isinstance(required, bool):
        violations.append(f"{param_where}: required must be a boolean")
    max_str_len = entry.get("max_str_len", 8192)
    if isinstance(max_str_len, bool) or not isinstance(max_str_len, int) or max_str_len < 1:
        violations.append(f"{param_where}: max_str_len must be a positive integer")
        return None
    if kind is None or role is None:
        return None
    return ToolParam(name=name, kind=kind, role=role, required=required, max_str_len=max_str_len)


def _parse_tool(entry: object, where: str, violations: list[str]) -> ToolSpec | None:
    """Parse one declared tool; ToolSpec/ToolParam own the deep validation."""
    if not isinstance(entry, dict):
        violations.append(f"{where}: tool must be a JSON object")
        return None
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        violations.append(f"{where}: tool name must be a non-empty string")
        return None

    effects: list[EffectClass] = []
    effects_raw = entry.get("effects")
    if not isinstance(effects_raw, list) or not effects_raw:
        violations.append(f"tool {name}: effects must be a non-empty list")
    else:
        for i, raw in enumerate(effects_raw):
            member = _member(raw, EffectClass, f"tool {name} effects[{i}]", violations)
            if member is not None:
                effects.append(member)

    requires_approval = entry.get("requires_approval")
    if requires_approval is not None and not isinstance(requires_approval, bool):
        violations.append(f"tool {name}: requires_approval must be a boolean or null")
        requires_approval = None

    params: list[ToolParam] = []
    params_raw = entry.get("params", [])
    if not isinstance(params_raw, list):
        violations.append(f"tool {name}: params must be a list")
    else:
        for param_entry in params_raw:
            param = _parse_param(param_entry, f"tool {name}", violations)
            if param is not None:
                params.append(param)

    if not effects:
        return None  # violations already recorded above; caller raises them all at once
    try:
        return ToolSpec(
            name=name,
            effects=frozenset(effects),
            params=tuple(params),
            requires_approval=requires_approval,
        )
    except ValueError as exc:  # name regex, dup/over-64 params
        violations.append(f"tool {where}: {exc}")
        return None


def registry_from_dict(data: Mapping[str, Any]) -> ToolRegistry:
    """Build a registry from the ``{"tools": [...]}`` wire shape.

    Every schema violation found across all tools is aggregated into one
    ``ValueError`` message; enum-valued fields are validated by membership,
    never passed through as raw strings.
    """
    tools = data.get("tools")
    if not isinstance(tools, list):
        raise ValueError("registry must be an object with a 'tools' list")

    violations: list[str] = []
    registry = ToolRegistry()
    for index, entry in enumerate(tools):
        where = f"tools[{index}]"
        spec = _parse_tool(entry, where, violations)
        if spec is None:
            continue
        try:
            registry.register(spec)
        except RegistryError as exc:
            violations.append(f"{where}: {exc}")
    if violations:
        joined = "\n".join(violations)
        raise ValueError(f"tool registry has {len(violations)} violation(s):\n{joined}")
    return registry
