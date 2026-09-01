"""RED contract tests for ``evals/gen_adaptive.py`` (adaptive-eval generator).

TDD red phase: ``evals/gen_adaptive.py`` does not exist yet, so this file fails
to collect with ModuleNotFoundError. Todo 3 must implement exactly the assumed
API below to turn it green -- do not weaken these assertions, satisfy them.

Assumed API (kept intentionally minimal):

- ``gen_adaptive.HELD_IN == "held_in"`` / ``gen_adaptive.HELD_OUT == "held_out"``
  (plain ``str`` split labels).
- ``gen_adaptive.generate(seed: int) -> list[dict]`` -- loads the fixed-corpus
  attack bases itself, runs the mutation library, assigns ``split``, and
  returns every in-memory row in a deterministic order. Row keys are exactly
  ``{id, expected_block, text, mutation, base_id, split}`` with
  ``id == f"{base_id}_{mutation}"``. For base64-family rows, ``text`` is the
  encoded payload itself (pure base64, no surrounding prose).
- ``gen_adaptive.write_rows(rows: list[dict], root: Path) -> None`` -- writes
  ``<root>/<dir_key(row)>/cases.jsonl``, one row per line, each line exactly
  ``json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
  + "\\n"`` (byte-stable for --regenerate).

RECONCILED (todo 3) against the final design; original intents kept intact:

- Layout is dir-per-``dir_key`` (``<transform>__<family>`` etc.), not
  dir-per-split; canonical bytes use compact separators + ``ensure_ascii``.
  Generation is pure in memory, so tests write only into ``tmp_path``.
- The split is MEASURED at generation (run today's guard): whitespace_split
  rows that the guard now catches become held-in tripwires, so that test
  asserts at least one measured held-out gap row plus per-row consistency with
  a fresh measurement instead of blanket held-out.
- ``generate`` also appends the 6 hand-authored benignmutate rows
  (``expected_block=False``); the schema test expects True only for
  attack-derived rows. The measured-split / self-block / uniqueness /
  determinism assertions are untouched.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evals"))

import gen_adaptive
from corpus import load_corpus

from llmsec import DecisionAction, Guard, Stage, Trust

_SEED = 2026
# Same tail relaxation as test_adaptive_mutations: multi-word codes carry "_".
_ID_RE = re.compile(r"^[a-z]+-\d+_[a-z0-9_]+$")
_FIXTURES = Path(__file__).resolve().parents[2] / "evals" / "fixtures"


def _rows() -> list[dict]:
    return gen_adaptive.generate(_SEED)


def test_split_labels_are_plain_strings() -> None:
    """The split vocabulary is two plain str constants, nothing fancier."""
    assert gen_adaptive.HELD_IN == "held_in"
    assert gen_adaptive.HELD_OUT == "held_out"
    assert isinstance(gen_adaptive.HELD_IN, str) and isinstance(gen_adaptive.HELD_OUT, str)


def test_generate_row_schema_and_split_values() -> None:
    """generate() returns non-empty rows keyed exactly
    {id, expected_block, text, mutation, base_id, split}; every split is one of
    the two labels and both labels occur. Attack-derived rows keep
    ``expected_block is True``; the 6 hand-authored benignmutate rows carry
    ``False`` (they must stay Allowed, guarding the benign FP budget)."""
    rows = _rows()
    assert rows
    splits = set()
    for row in rows:
        assert set(row) == {"id", "expected_block", "text", "mutation", "base_id", "split"}
        if row["mutation"] == "benignmutate":
            assert row["expected_block"] is False, row["id"]
        else:
            assert row["expected_block"] is True, row["id"]
        assert row["id"] == f"{row['base_id']}_{row['mutation']}"
        assert row["split"] in {gen_adaptive.HELD_IN, gen_adaptive.HELD_OUT}
        splits.add(row["split"])
    assert splits == {gen_adaptive.HELD_IN, gen_adaptive.HELD_OUT}


def test_generate_is_deterministic_same_seed() -> None:
    """Two in-memory generations with the same seed must be byte-identical,
    including list order (no set iteration anywhere)."""
    first, second = gen_adaptive.generate(_SEED), gen_adaptive.generate(_SEED)
    assert first == second
    assert [json.dumps(r, sort_keys=True) for r in first] == [
        json.dumps(r, sort_keys=True) for r in second
    ]


def test_generated_ids_unique_and_disjoint_from_fixed_corpus() -> None:
    """Generated ids match the "<base_id>_<code>" form, are globally unique,
    and never shadow an id from the fixed evals/fixtures corpus."""
    rows = _rows()
    corpus_ids = {case.id for case in load_corpus(_FIXTURES)}
    ids = [row["id"] for row in rows]
    assert len(set(ids)) == len(ids)
    for row_id in ids:
        assert _ID_RE.fullmatch(row_id), row_id
        assert row_id not in corpus_ids


def test_held_in_rows_self_block_under_default_guard() -> None:
    """The self-check invariant: a held-IN row must be detected by today's
    guard, i.e. the decision action is not ALLOW at retrieval/untrusted.
    (diagnostics=True is a Guard.default() constructor kwarg, not an
    inspect() argument.)"""
    guard = Guard.default(diagnostics=True)
    held_in = [row for row in _rows() if row["split"] == gen_adaptive.HELD_IN]
    assert held_in, "generate() must produce held-in rows"
    for row in held_in:
        decision = guard.inspect(
            row["text"],
            stage=Stage.RETRIEVAL_DOCUMENT,
            trust=Trust.UNTRUSTED,
        )
        assert decision.action != DecisionAction.ALLOW, (
            f"held-in row {row['id']} ({row['mutation']}) self-evades: {decision.action}"
        )


def test_whitespace_split_rows_use_measured_split() -> None:
    """Calibrated gap: whitespace_split breaks the word-boundary heuristic on
    SOME bases, so at least one such row is a measured held-OUT gap. Splits are
    measured at generation, so rows the guard does catch become held-IN
    tripwires: every row's label must match a fresh measurement here."""
    guard = Guard.default(diagnostics=True)
    rows = [row for row in _rows() if row["mutation"] == "whitespace_split"]
    assert rows, "generate() must include whitespace_split rows"
    assert any(row["split"] == gen_adaptive.HELD_OUT for row in rows), (
        "generate() must include measured held-out whitespace_split gap rows"
    )
    for row in rows:
        decision = guard.inspect(
            row["text"],
            stage=Stage.RETRIEVAL_DOCUMENT,
            trust=Trust.UNTRUSTED,
        )
        allowed = decision.action == DecisionAction.ALLOW
        want = gen_adaptive.HELD_OUT if allowed else gen_adaptive.HELD_IN
        assert row["split"] == want, row["id"]


def test_write_rows_writes_canonical_jsonl_per_dir_key(tmp_path: Path) -> None:
    """write_rows(rows, root) creates exactly <root>/<dir_key(row)>/cases.jsonl
    for the dir keys present, holding that dir's rows in generate() order, each
    line byte-equal to json.dumps(row, sort_keys=True, ensure_ascii=True,
    separators=(",", ":")) + newline. Only tmp_path is touched: generate() is
    pure in memory and write_rows writes to the explicit root."""
    rows = _rows()
    gen_adaptive.write_rows(rows, tmp_path)
    dir_keys = {gen_adaptive.dir_key(row) for row in rows}
    expected_files = {tmp_path / name / "cases.jsonl" for name in dir_keys}
    assert expected_files == set(tmp_path.rglob("cases.jsonl"))
    fixed_families = {case.family for case in load_corpus(_FIXTURES)}
    assert not dir_keys & fixed_families
    for name in dir_keys:
        body = (tmp_path / name / "cases.jsonl").read_text(encoding="utf-8")
        assert body.endswith("\n")
        lines = body.splitlines()
        dir_rows = [row for row in rows if gen_adaptive.dir_key(row) == name]
        assert lines == [
            json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            for row in dir_rows
        ]
        assert all(line.isascii() for line in lines)
