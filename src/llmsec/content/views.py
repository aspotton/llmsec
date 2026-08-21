import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_MAX_ENCODED_CANDIDATE = 2048
_MAX_DECODED_CANDIDATE = 4096
_MAX_CANDIDATES = 8

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


@dataclass(frozen=True, slots=True)
class DecodedCandidate:
    kind: str
    source: str
    decoded: str


@dataclass(frozen=True, slots=True)
class ContentViews:
    raw: str
    nfkc: str
    visible_controls_removed: str
    decoded_candidates: tuple[DecodedCandidate, ...]


def _printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    printable = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return printable / len(value)


def _decode_base64_candidates(text: str) -> tuple[DecodedCandidate, ...]:
    candidates: list[DecodedCandidate] = []
    for match in _BASE64_RE.finditer(text):
        if len(candidates) >= _MAX_CANDIDATES:
            break
        source = match.group(0)
        if len(source) > _MAX_ENCODED_CANDIDATE:
            continue
        try:
            raw = base64.b64decode(source, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) > _MAX_DECODED_CANDIDATE:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded) < 0.85:
            continue
        candidates.append(DecodedCandidate(kind="base64", source=source, decoded=decoded))
    return tuple(candidates)


def _remove_invisible_controls(text: str) -> str:
    return "".join(
        character
        for character in text
        if character not in _ZERO_WIDTH and character not in _BIDI_CONTROLS
    )


def build_content_views(text: str) -> ContentViews:
    """Build bounded, immutable representations once for reuse by all detectors."""

    return ContentViews(
        raw=text,
        nfkc=unicodedata.normalize("NFKC", text),
        visible_controls_removed=_remove_invisible_controls(text),
        decoded_candidates=_decode_base64_candidates(text),
    )
