import re

from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Severity, Stage
from llmsec.detectors.base import DetectorSpec

_REPEATED_CHAR = re.compile(r"(.)\1{127,}", re.DOTALL)
_REPEATED_WORD = re.compile(r"\b([A-Za-z]{2,})\b(?:\s+\1\b){63,}", re.IGNORECASE)


class ContextAnomalyDetector:
    spec = DetectorSpec(
        name="context_anomaly",
        stages=frozenset(Stage),
        cost=DetectorCost.LINEAR,
        timeout_ms=8,
    )

    async def inspect(self, context: SecurityContext, views: ContentViews) -> list[Finding]:
        del context
        findings: list[Finding] = []

        repeated = _REPEATED_CHAR.search(views.raw) or _REPEATED_WORD.search(views.raw)
        if repeated:
            findings.append(
                Finding(
                    detector=self.spec.name,
                    category="context_padding",
                    confidence=0.88,
                    severity=Severity.MEDIUM,
                    message="Large repeated padding sequence detected.",
                    spans=((repeated.start(), repeated.end()),),
                )
            )

        if len(views.raw) >= 1000:
            whitespace_ratio = sum(character.isspace() for character in views.raw) / len(views.raw)
            if whitespace_ratio >= 0.85:
                findings.append(
                    Finding(
                        detector=self.spec.name,
                        category="whitespace_padding",
                        confidence=0.86,
                        severity=Severity.MEDIUM,
                        message="Content contains an unusually high amount of whitespace padding.",
                    )
                )
        return findings
