import re

from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Severity, Stage
from llmsec.detectors.base import DetectorSpec

_INJECTION_HINT = re.compile(
    r"\b(ignore|override|bypass|system\s+prompt|previous\s+instructions?|reveal\s+.*prompt)\b",
    re.IGNORECASE,
)


class EncodingDetector:
    spec = DetectorSpec(
        name="encoding",
        stages=frozenset(Stage),
        cost=DetectorCost.LINEAR,
        timeout_ms=8,
    )

    async def inspect(self, context: SecurityContext, views: ContentViews) -> list[Finding]:
        del context
        if not views.decoded_candidates:
            return []

        decoded_with_injection_hint = [
            candidate
            for candidate in views.decoded_candidates
            if _INJECTION_HINT.search(candidate.decoded)
        ]
        if decoded_with_injection_hint:
            return [
                Finding(
                    detector=self.spec.name,
                    category="encoded_instruction",
                    confidence=0.94,
                    severity=Severity.HIGH,
                    message="Encoded content decodes to instruction-like security-sensitive text.",
                    properties={
                        "encodings": tuple(
                            sorted({candidate.kind for candidate in decoded_with_injection_hint})
                        )
                    },
                )
            ]

        return [
            Finding(
                detector=self.spec.name,
                category="encoded_content",
                confidence=0.62,
                severity=Severity.MEDIUM,
                message="Encoded printable content was detected and decoded for inspection.",
                properties={
                    "encodings": tuple(
                        sorted({candidate.kind for candidate in views.decoded_candidates})
                    )
                },
            )
        ]
