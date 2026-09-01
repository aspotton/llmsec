"""Deterministic generator for the adaptive-eval corpus (roadmap-08 track).

Stdlib-only. Complements the fixed benchmark in ``evals/fixtures`` (see
``evals/AGENTS.md``): this corpus is *generated* from the fixed attack bases via
the seeded mutation ladder in ``mutations.py``, never hand-written, and lives
separately under ``evals/adaptive/fixtures``.

Split semantics are MEASURED, not asserted: at generation time every row is run
through ``Guard.default(diagnostics=True)`` at the untrusted retrieval boundary
and ``split`` records what today's detectors actually did. ``held_in`` rows were
measured-block and are regression tripwires; ``held_out`` rows were measured-
Allow and are published detection gaps (plus the benignmutate FP-budget rows,
which must stay Allowed). ``mutations.SPLIT`` is only the fallback prior the
measurement validates: a static held-in candidate that slips past the guard
aborts generation (mislabel guard), and a blocked benignmutate row aborts too
(benign FP budget). Re-running with the same seed must reproduce the fixture
bytes; ``--regenerate`` enforces that.
"""

import argparse
import base64
import difflib
import json
import random
import re
import sys
from pathlib import Path

# Repo bootstrap idiom (same as corpus.py / run_eval.py): resolve the runtime
# package from the source tree so `python3 evals/gen_adaptive.py` works.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

import mutations  # noqa: E402
from corpus import EvalCase, load_corpus  # noqa: E402

from llmsec import DecisionAction, Guard, Stage, Trust  # noqa: E402
from llmsec.detectors.encoding import _INJECTION_HINT  # noqa: E402

# Plain str split labels (the row schema stays JSON-serialisable).
HELD_IN = "held_in"
HELD_OUT = "held_out"

DEFAULT_SEED = 20260831
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_OUT = Path(__file__).resolve().parent / "adaptive" / "fixtures"

# benignmutate rows are hand-authored (no TRANSFORMS/SPLIT entry): the 6 benign
# fixtures whose text carries attack-adjacent detector vocabulary, perturbed
# with whitespace_split -- the mutation measured ALLOW on all 6 (zero_width
# U+200B-in-prose measured BLOCK and would burn the benign FP budget).
_BENIGN_MUTATE = "benignmutate"
_BENIGN_MUTATE_DIR = "benignmutate__handauthored"
_ATTACK_ADJACENT = re.compile(
    r"\b(?:system prompt|disregard|forget|repeat|dump|secret)\w*\b", re.IGNORECASE
)
_FIXED_FAMILIES = frozenset(
    {
        "benign",
        "fake_authority",
        "instruction_override",
        "secrets_obfuscation",
        "system_prompt_extraction",
    }
)

_BASES: dict[str, EvalCase] | None = None


def _bases_by_id() -> dict[str, EvalCase]:
    """Lazily index the fixed corpus by id (dir_key needs the base text)."""
    global _BASES
    if _BASES is None:
        _BASES = {case.id: case for case in load_corpus(_FIXTURES)}
    return _BASES


def dir_key(row: dict) -> str:
    """Map a row to its fixture directory ``<transform>__<source_family>``.

    Two routings override the generic name: a base64_nest2 row over a base that
    already embeds a base64 literal lands in ``b64_literal_nest2__<family>``
    (the double-wrap of a literal, not a plain nesting), and a base64_wrap row
    whose decode carries no injection hint (should be unreachable thanks to
    ``mutations._payload``) lands in ``base64_hint_miss__<family>``.
    """
    if row["mutation"] == _BENIGN_MUTATE:
        return _BENIGN_MUTATE_DIR
    base = _bases_by_id()[row["base_id"]]
    if row["mutation"] == "base64_nest2" and mutations._BASE64_LITERAL_RE.search(base.text):
        return f"b64_literal_nest2__{base.family}"
    if row["mutation"] == "base64_wrap":
        decoded = base64.b64decode(row["text"], validate=False).decode("utf-8", "replace")
        if not _INJECTION_HINT.search(decoded):
            return f"base64_hint_miss__{base.family}"
    return f"{row['mutation']}__{base.family}"


def _benign_mutate_rows(cases: list[EvalCase], rng: random.Random) -> list[dict]:
    """Hand-authored benign FP-budget rows: attack-adjacent benign text, lightly
    perturbed, expected to STAY Allowed. Exactly 6 fixtures qualify; a fixture
    edit that changes that count aborts rather than silently shifting the budget."""
    selected = sorted(
        (c for c in cases if not c.expected_block and _ATTACK_ADJACENT.search(c.text)),
        key=lambda c: c.id,
    )
    if len(selected) != 6:  # the pinned benign-FP budget
        raise SystemExit(
            f"benignmutate expects exactly 6 attack-adjacent benign fixtures, found {len(selected)}"
        )
    return [
        {
            "id": f"{case.id}_{_BENIGN_MUTATE}",
            "expected_block": False,
            "text": mutations.TRANSFORMS["whitespace_split"](case.text, rng)[0],
            "mutation": _BENIGN_MUTATE,
            "base_id": case.id,
        }
        for case in selected
    ]


def _assign_splits(rows: list[dict]) -> None:
    """Measure every row against today's guard and record the split in place.

    ALLOW -> held_out (published gap), anything else -> held_in (tripwire). Two
    drift guards abort generation: a row the static registry expected to block
    that the guard now Allows, and a benignmutate row the guard now blocks.
    """
    guard = Guard.default(diagnostics=True)
    mislabeled: list[str] = []
    false_positives: list[str] = []
    for row in rows:
        decision = guard.inspect(
            row["text"],
            stage=Stage.RETRIEVAL_DOCUMENT,
            trust=Trust.UNTRUSTED,
        )
        allowed = decision.action == DecisionAction.ALLOW
        row["split"] = HELD_OUT if allowed else HELD_IN
        if row["expected_block"]:
            if mutations.SPLIT.get(row["mutation"], HELD_IN) == HELD_IN and allowed:
                mislabeled.append(row["id"])
        elif not allowed:
            false_positives.append(row["id"])
    if mislabeled:
        raise SystemExit(f"static held-in rows self-evade today's guard: {', '.join(mislabeled)}")
    if false_positives:
        raise SystemExit(f"benignmutate rows would block (FP budget): {', '.join(false_positives)}")


def generate(seed: int) -> list[dict]:
    """Generate every adaptive row in memory (no IO): 348 mutation rows over the
    42 attack bases + 6 benignmutate rows, split measured against the guard."""
    cases = load_corpus(_FIXTURES)
    bases = sorted((c for c in cases if c.expected_block), key=lambda c: c.id)
    rows = mutations.generate_mutations(bases, seed)
    rows.extend(_benign_mutate_rows(cases, random.Random(seed)))
    _assign_splits(rows)
    dirs = {dir_key(row) for row in rows}
    clash = dirs & _FIXED_FAMILIES
    if clash:
        raise SystemExit(f"generated dir names collide with fixed families: {sorted(clash)}")
    return rows


def _line(row: dict) -> str:
    """One canonical JSONL record: sorted keys, ASCII-only, compact separators."""
    return json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"


def _grouped(rows: list[dict]) -> dict[str, list[dict]]:
    """Rows bucketed by dir_key, first-appearance order preserved inside each."""
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(dir_key(row), []).append(row)
    return groups


def write_rows(rows: list[dict], root: Path) -> None:
    """Write ``<root>/<dir_key>/cases.jsonl``, canonical bytes, generate() order."""
    for name, group in sorted(_grouped(rows).items()):
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        body = "".join(_line(row) for row in group)
        (directory / "cases.jsonl").write_text(body, encoding="utf-8")


def _regenerate(seed: int) -> int:
    """Byte-compare regenerated rows against every file under _OUT (no writes)."""
    grouped = _grouped(generate(seed))
    expected = {name: "".join(_line(row) for row in group) for name, group in grouped.items()}
    drifted = False
    for name in sorted(set(expected) | {p.parent.name for p in _OUT.glob("*/cases.jsonl")}):
        path = _OUT / name / "cases.jsonl"
        want = expected.get(name)
        if want is None:
            print(f"DRIFT (unexpected file): {path}")
            drifted = True
            continue
        if not path.is_file():
            print(f"DRIFT (missing): {path}")
            drifted = True
            continue
        have = path.read_text(encoding="utf-8")
        if have != want:
            print(f"DRIFT: {path}")
            print(
                "".join(
                    difflib.unified_diff(
                        have.splitlines(keepends=True),
                        want.splitlines(keepends=True),
                        fromfile=str(path),
                        tofile="<regenerated>",
                    )
                )
            )
            drifted = True
    if drifted:
        return 1
    print(f"byte-match: {len(expected)} files under {_OUT}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="rebuild in memory and byte-compare against evals/adaptive/fixtures (writes nothing)",
    )
    args = parser.parse_args()
    if args.regenerate:
        return _regenerate(args.seed)
    rows = generate(args.seed)
    write_rows(rows, _OUT)
    held_in = sum(1 for row in rows if row["split"] == HELD_IN)
    print(
        f"wrote {len(rows)} rows ({held_in} held_in / {len(rows) - held_in} held_out) "
        f"across {len(_grouped(rows))} dirs under {_OUT}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
