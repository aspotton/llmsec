from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Severity, Stage
from llmsec.detectors.base import DetectorSpec

_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_BIDI_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


class UnicodeDetector:
    spec = DetectorSpec(
        name="unicode",
        stages=frozenset(Stage),
        cost=DetectorCost.LINEAR,
        timeout_ms=5,
    )

    async def inspect(self, context: SecurityContext, views: ContentViews) -> list[Finding]:
        del context
        findings: list[Finding] = []
        suspicious_spans: list[tuple[int, int]] = []
        mechanisms: set[str] = set()

        for index, character in enumerate(views.raw):
            codepoint = ord(character)
            if character in _ZERO_WIDTH:
                suspicious_spans.append((index, index + 1))
                mechanisms.add("zero_width")
            elif character in _BIDI_CONTROLS:
                suspicious_spans.append((index, index + 1))
                mechanisms.add("bidi_control")
            elif 0xE0000 <= codepoint <= 0xE007F:
                suspicious_spans.append((index, index + 1))
                mechanisms.add("unicode_tag")
            elif 0xE0100 <= codepoint <= 0xE01EF:
                suspicious_spans.append((index, index + 1))
                mechanisms.add("variation_selector_supplement")

        if suspicious_spans:
            findings.append(
                Finding(
                    detector=self.spec.name,
                    category="unicode_obfuscation",
                    confidence=0.96,
                    severity=Severity.HIGH,
                    message=(
                        "Suspicious invisible or direction-changing Unicode characters detected."
                    ),
                    spans=tuple(suspicious_spans[:32]),
                    properties={"mechanisms": tuple(sorted(mechanisms))},
                )
            )
        return findings
