from dataclasses import dataclass
from typing import Protocol

from llmsec.core import Decision, DecisionAction, Finding, SecurityContext, Severity

_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Policy(Protocol):
    def decide(
        self,
        *,
        content: str,
        context: SecurityContext,
        findings: tuple[Finding, ...],
        metrics: dict[str, float],
    ) -> Decision: ...


@dataclass(frozen=True, slots=True)
class DefaultPolicy:
    block_threshold: float = 0.90
    minimum_block_severity: Severity = Severity.HIGH

    def decide(
        self,
        *,
        content: str,
        context: SecurityContext,
        findings: tuple[Finding, ...],
        metrics: dict[str, float],
    ) -> Decision:
        del context
        risk = max((finding.confidence for finding in findings), default=0.0)
        should_block = any(
            finding.confidence >= self.block_threshold
            and _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[self.minimum_block_severity]
            for finding in findings
        )
        action = DecisionAction.BLOCK if should_block else DecisionAction.ALLOW
        return Decision(
            action=action,
            content=content,
            findings=findings,
            risk=risk,
            metrics=metrics,
        )
