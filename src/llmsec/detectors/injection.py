import re

from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Severity, Stage, Trust
from llmsec.detectors.base import DetectorSpec

_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|override|forget)\b.{0,48}"
            r"\b(?:previous|prior|above|system|developer)\b.{0,32}"
            r"\b(?:instructions?|rules?|prompt)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.96,
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"\b(?:reveal|show|print|repeat|dump|expose)\b.{0,48}"
            r"\b(?:system|developer)\b.{0,16}"
            r"\b(?:prompt|instructions?|message)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.94,
    ),
    (
        "fake_authority",
        re.compile(
            r"\b(?:system\s+(?:message|override|instruction)|developer\s+message|"
            r"user\s+(?:approved|authorized))\b",
            re.IGNORECASE,
        ),
        0.89,
    ),
)


class HeuristicInjectionDetector:
    """Bootstrap detector only; replace/augment with a calibrated semantic model later."""

    spec = DetectorSpec(
        name="heuristic_injection",
        stages=frozenset(
            {
                Stage.USER_INPUT,
                Stage.RETRIEVAL_DOCUMENT,
                Stage.TOOL_RESULT,
            }
        ),
        cost=DetectorCost.LINEAR,
        timeout_ms=8,
    )

    async def inspect(self, context: SecurityContext, views: ContentViews) -> list[Finding]:
        findings: list[Finding] = []
        # Scan decoded payloads too (base64/rot13 candidates): an encoded attack is
        # the same wording once decoded. FP-safety is pinned by
        # tests/unit/test_injection_fp_harness.py (no benign decoded surface matches).
        search_views = (
            views.raw,
            views.nfkc,
            views.visible_controls_removed,
            *(candidate.decoded for candidate in views.decoded_candidates),
        )

        for category, pattern, base_confidence in _PATTERNS:
            match = None
            for value in search_views:
                match = pattern.search(value)
                if match is not None:
                    break
            if match is None:
                continue

            confidence = base_confidence
            if context.stage in {Stage.RETRIEVAL_DOCUMENT, Stage.TOOL_RESULT}:
                confidence = min(1.0, confidence + 0.02)
            if context.trust is Trust.UNTRUSTED:
                confidence = min(1.0, confidence + 0.01)

            findings.append(
                Finding(
                    detector=self.spec.name,
                    category="prompt_injection",
                    confidence=confidence,
                    severity=Severity.HIGH,
                    message=f"Injection-like pattern detected ({category}).",
                    properties={"pattern": category},
                )
            )
        return findings
