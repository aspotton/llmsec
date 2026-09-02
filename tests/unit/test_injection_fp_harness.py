"""FP-proof harness for scanning decoded candidates with the injection patterns.

rot13-of-English is English-shaped, so wiring ``HeuristicInjectionDetector``
onto ``views.decoded_candidates`` is only false-positive-safe if no benign
decoded surface actually matches ``_PATTERNS``. This test is that proof, and
it must stay green before the wiring counts as complete:

* negative: zero ``_PATTERNS`` match on any surface (raw, nfkc,
  visible_controls_removed, every ``decoded_candidates[*].decoded``) of every
  benign text — the 6 attack-adjacent benignmutate rows that carry the pinned
  benign FP budget, plus every ``expected_block == False`` fixed fixture.
* positive: every published rot13 gap row matches on a decoded candidate and
  therefore blocks at the untrusted retrieval boundary.

Private import of ``_PATTERNS`` is acceptable here for the same reason as in
``test_eval_scorer.py``: the guard is against detector-implementation drift.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evals"))

from corpus import load_corpus

from llmsec import DecisionAction, Guard, Stage, Trust
from llmsec.content import build_content_views
from llmsec.detectors.injection import _PATTERNS

_ROOT = Path(__file__).resolve().parents[2]
_ADAPTIVE = _ROOT / "evals" / "adaptive"


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _benign_texts() -> list[str]:
    mutate_rows = _rows(_ADAPTIVE / "fixtures" / "benignmutate__handauthored" / "cases.jsonl")
    assert len(mutate_rows) == 6  # the pinned benign FP budget
    fixture_cases = [
        case for case in load_corpus(_ROOT / "evals" / "fixtures") if not case.expected_block
    ]
    return [row["text"] for row in mutate_rows] + [case.text for case in fixture_cases]


def _surfaces(text: str) -> list[str]:
    view = build_content_views(text)
    return [
        view.raw,
        view.nfkc,
        view.visible_controls_removed,
        *(candidate.decoded for candidate in view.decoded_candidates),
    ]


def test_benign_surfaces_never_match_injection_patterns() -> None:
    texts = _benign_texts()
    assert len(texts) == 18  # 6 benignmutate + 12 benign fixtures
    for text in texts:
        for surface in _surfaces(text):
            for name, pattern, _ in _PATTERNS:
                assert not pattern.search(surface), (
                    f"{name} matched benign surface {surface[:60]!r}"
                )


# The 19 rot13 rows that were published gaps when the decoded-candidate scan
# landed (pinned from the pre-wiring gap baseline; the current baseline lists
# none because these rows closed). The other 17 rot13 rows were already blocked
# by other detectors -- io-010/011/012 carry zero-width or full-width letters in
# their plaintext, so no injection pattern ever matches their decoded surface.
_F1_ROT13_GAP_ROWS = frozenset(
    {
        "fa-001_rot13",
        "fa-003_rot13",
        "fa-004_rot13",
        "fa-005_rot13",
        "fa-006_rot13",
        "fa-009_rot13",
        "fa-010_rot13",
        "fa-011_rot13",
        "fa-012_rot13",
        "io-004_rot13",
        "io-006_rot13",
        "io-008_rot13",
        "spe-002_rot13",
        "spe-003_rot13",
        "spe-005_rot13",
        "spe-007_rot13",
        "spe-009_rot13",
        "spe-010_rot13",
        "spe-011_rot13",
    }
)


def test_rot13_rows_all_block_and_f1_gaps_match_decoded_candidates() -> None:
    guard = Guard.default()
    seen: set[str] = set()
    for path in sorted((_ADAPTIVE / "fixtures").glob("rot13__*/cases.jsonl")):
        for row in _rows(path):
            seen.add(row["id"])
            if row["id"] in _F1_ROT13_GAP_ROWS:
                decoded = [
                    candidate.decoded
                    for candidate in build_content_views(row["text"]).decoded_candidates
                ]
                assert any(
                    pattern.search(value) for _, pattern, _ in _PATTERNS for value in decoded
                ), row["id"]
            decision = guard.inspect(
                row["text"], stage=Stage.RETRIEVAL_DOCUMENT, trust=Trust.UNTRUSTED
            )
            assert decision.action is not DecisionAction.ALLOW, row["id"]
    assert seen >= _F1_ROT13_GAP_ROWS and len(seen) == 36
