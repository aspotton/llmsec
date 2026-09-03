import base64
import binascii
import codecs
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
# Invisible operators (U+2061..U+2064): zero-width, so they can split a secret
# literal without a visible gap. U+2060 is already in _ZERO_WIDTH.
_INVISIBLE_OPERATORS = {"\u2061", "\u2062", "\u2063", "\u2064"}


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


def _decode_base64_once(source: str) -> str | None:
    """Decode one base64 token under the shared size/printability bounds."""

    if len(source) > _MAX_ENCODED_CANDIDATE:
        return None
    try:
        raw = base64.b64decode(source, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > _MAX_DECODED_CANDIDATE:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable_ratio(decoded) < 0.85:
        return None
    return decoded


def _rot13(text: str) -> str:
    """ROT13 ASCII letters only; every other code point passes through."""

    return codecs.decode(text, "rot_13")


def _decoded_candidates(text: str) -> tuple[DecodedCandidate, ...]:
    """Build bounded decode candidates once: depth-2 base64 (breadth-first) then rot13."""

    candidates: list[DecodedCandidate] = []
    seen: set[str] = set()

    def emit(kind: str, source: str, decoded: str) -> None:
        if len(candidates) >= _MAX_CANDIDATES or decoded in seen:
            return
        seen.add(decoded)
        candidates.append(DecodedCandidate(kind=kind, source=source, decoded=decoded))

    # Depth 1: base64 tokens in the raw text.
    depth1: list[str] = []
    for match in _BASE64_RE.finditer(text):
        if len(candidates) >= _MAX_CANDIDATES:
            break
        decoded = _decode_base64_once(match.group(0))
        if decoded is None:
            continue
        depth1.append(decoded)
        emit("base64", match.group(0), decoded)

    # Depth 2, breadth-first (all depth-1 slots fill before any depth-2): one more
    # decode over each depth-1 payload. `decoded` is stored flattened end-to-end so
    # unchanged consumers such as the encoding hint check see the final payload.
    # Bounded at depth 2; no rot13-of-decoded combos (YAGNI).
    for inner in depth1:
        if len(candidates) >= _MAX_CANDIDATES:
            break
        for match in _BASE64_RE.finditer(inner):
            decoded = _decode_base64_once(match.group(0))
            if decoded is not None:
                emit("base64x2", match.group(0), decoded)

    # rot13 of the raw text, emitted last. Shape gate is noise-suppression only
    # (long mostly-alphabetic text); false-positive safety comes from English
    # prose never decoding through rot13 into injection-shaped wording.
    if len(text) >= 16:
        rotated = _rot13(text)
        alphabetic = sum(character.isalpha() for character in text) / len(text)
        if alphabetic >= 0.75 and _printable_ratio(rotated) >= 0.85:
            emit("rot13", text, rotated)

    return tuple(candidates)


def _remove_invisible_controls(text: str) -> str:
    return "".join(
        character
        for character in text
        if character not in _ZERO_WIDTH
        and character not in _BIDI_CONTROLS
        and character not in _INVISIBLE_OPERATORS
    )


def build_content_views(text: str) -> ContentViews:
    """Build bounded, immutable representations once for reuse by all detectors."""

    return ContentViews(
        raw=text,
        nfkc=unicodedata.normalize("NFKC", text),
        visible_controls_removed=_remove_invisible_controls(text),
        decoded_candidates=_decoded_candidates(text),
    )
