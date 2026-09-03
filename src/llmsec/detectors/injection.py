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

# The whitespace/hyphen split mutations break a keyword token after its second
# character ("Ignore" -> "Ig nore" / "Ig-nore"), so the word-boundary keyword
# literals above no longer match even though every keyword is present. These
# loose variants keep the exact ``.{0,N}``/``\s+`` gaps of ``_PATTERNS`` and only
# interleave each keyword's letters with an optional split separator, so they
# re-arm the same three detectors against de-splittable input. Scanned ONLY on
# the raw and NFKC surfaces (never the decoded candidates) to avoid widening the
# decoded-surface FP set; false-positive safety is pinned by
# tests/unit/test_injection_fp_harness.py.


def _loose(literal: str) -> str:
    """Interleave a keyword's letters with an optional whitespace/hyphen slot."""
    return r"[\s-]?".join(re.escape(character) for character in literal)


def _loose_plural(stem: str, suffix: str) -> str:
    """Loose keyword with an optional plural suffix (``instructions?``)."""
    return _loose(stem) + r"(?:[\s-]?" + re.escape(suffix) + ")?"


def _alt(variants: list[str]) -> str:
    """Non-capturing alternation of already-escaped pattern fragments."""
    return "(?:" + "|".join(variants) + ")"


_LOOSE_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b"
            + _alt([_loose(word) for word in ("ignore", "disregard", "override", "forget")])
            + r"\b.{0,48}\b"
            + _alt([_loose(word) for word in ("previous", "prior", "above", "system", "developer")])
            + r"\b.{0,32}\b"
            + _alt(
                [
                    _loose_plural("instruction", "s"),
                    _loose_plural("rule", "s"),
                    _loose("prompt"),
                ]
            )
            + r"\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.96,
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"\b"
            + _alt(
                [_loose(word) for word in ("reveal", "show", "print", "repeat", "dump", "expose")]
            )
            + r"\b.{0,48}\b"
            + _alt([_loose(word) for word in ("system", "developer")])
            + r"\b.{0,16}\b"
            + _alt([_loose("prompt"), _loose_plural("instruction", "s"), _loose("message")])
            + r"\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.94,
    ),
    (
        "fake_authority",
        re.compile(
            r"\b(?:"
            + _loose("system")
            + r"\s+(?:"
            + _alt([_loose("message"), _loose("override"), _loose("instruction")])
            + ")|"
            + _loose("developer")
            + r"\s+"
            + _loose("message")
            + "|"
            + _loose("user")
            + r"\s+(?:"
            + _alt([_loose("approved"), _loose("authorized")])
            + "))\b",
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
        # Scan decoded payloads too (base64/rot13 candidates): an encoded attack is
        # the same wording once decoded. FP-safety is pinned by
        # tests/unit/test_injection_fp_harness.py (no benign decoded surface matches).
        search_views = (
            views.raw,
            views.nfkc,
            views.visible_controls_removed,
            *(candidate.decoded for candidate in views.decoded_candidates),
        )
        # Loose variants scan only the raw and NFKC surfaces (decoded candidates
        # keep the base patterns), so a de-split attack is caught without widening
        # the decoded-surface FP surface.
        loose_views = (views.raw, views.nfkc)

        return self._match(context, _PATTERNS, search_views) + self._match(
            context, _LOOSE_PATTERNS, loose_views
        )

    def _match(
        self,
        context: SecurityContext,
        patterns: tuple[tuple[str, re.Pattern[str], float], ...],
        surfaces: tuple[str, ...],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for category, pattern, base_confidence in patterns:
            match = None
            for value in surfaces:
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
