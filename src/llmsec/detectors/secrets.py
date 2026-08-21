import re

from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Severity, Stage
from llmsec.detectors.base import DetectorSpec

_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity, float], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.HIGH,
        0.99,
    ),
    (
        "aws_access_key_id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.HIGH,
        0.98,
    ),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{16,}"
        ),
        Severity.MEDIUM,
        0.82,
    ),
)


class SecretDetector:
    spec = DetectorSpec(
        name="secrets",
        stages=frozenset(Stage),
        cost=DetectorCost.LINEAR,
        timeout_ms=5,
    )

    async def inspect(self, context: SecurityContext, views: ContentViews) -> list[Finding]:
        del context
        findings: list[Finding] = []
        for category, pattern, severity, confidence in _PATTERNS:
            for match in pattern.finditer(views.raw):
                findings.append(
                    Finding(
                        detector=self.spec.name,
                        category=category,
                        confidence=confidence,
                        severity=severity,
                        message=f"Possible {category.replace('_', ' ')} detected.",
                        spans=((match.start(), match.end()),),
                    )
                )
        return findings
