from collections.abc import Mapping
from dataclasses import dataclass, field

from llmsec.core.enums import DecisionAction
from llmsec.core.finding import Finding


@dataclass(frozen=True, slots=True)
class Decision:
    action: DecisionAction
    content: str
    findings: tuple[Finding, ...] = ()
    risk: float = 0.0
    metrics: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be between 0.0 and 1.0")

    @property
    def allowed(self) -> bool:
        return self.action in {DecisionAction.ALLOW, DecisionAction.SANITIZE}

    @property
    def blocked(self) -> bool:
        return self.action is DecisionAction.BLOCK
