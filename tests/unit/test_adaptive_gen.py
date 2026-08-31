"""RED contract tests for ``evals/gen_adaptive.py`` (adaptive-eval generator).

TDD red phase: ``evals/gen_adaptive.py`` does not exist yet, so this file fails
to collect with ModuleNotFoundError. Todo 3 must implement exactly the assumed
API below to turn it green — do not weaken these assertions, satisfy them.

Assumed API (kept intentionally minimal):

- ``gen_adaptive.HELD_IN == "held_in"`` / ``gen_adaptive.HELD_OUT == "held_out"``
  (plain ``str`` split labels).
- ``gen_adaptive.generate(seed: int) -> list[dict]`` — loads the fixed-corpus
  attack bases itself, runs the mutation library, assigns ``split``, and
  returns every in-memory row in a deterministic order. Row keys are exactly
  ``{id, expected_block, text, mutation, base_id, split}`` with
  ``id == f"{base_id}_{mutation}"``. For base64-family rows, ``text`` is the
  encoded payload itself (pure base64, no surrounding prose).
- ``gen_adaptive.write_rows(rows: list[dict], root: Path) -> None`` — writes
  ``<root>/<split>/cases.jsonl``, one row per line, each line exactly
  ``json.dumps(row, sort_keys=True) + "\\n"`` (byte-stable for --regenerate).

Split rule pinned here (calibrated against the shipped detectors):
whitespace_split evades the word-boundary heuristic, so its rows are held-OUT;
every other generated row must self-block under Guard.default and is held-IN.
The ``--regenerate`` byte-compare contract (re-running the writer over a fresh
seed must reproduce the fixture bytes) is exercised by the CI step, not here,
to keep the assumed surface to ``generate``/``write_rows``.
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
    the two labels, both labels occur, and expected_block is True throughout
    (benign-mutate rows are hand-authored, never generated)."""
    rows = _rows()
    assert rows
    splits = set()
    for row in rows:
        assert set(row) == {"id", "expected_block", "text", "mutation", "base_id", "split"}
        assert row["expected_block"] is True
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


def test_whitespace_split_rows_are_held_out() -> None:
    """Calibrated gap: whitespace_split breaks the word-boundary heuristic, so
    those rows exist and are assigned to the held-OUT split, never held-in."""
    rows = [row for row in _rows() if row["mutation"] == "whitespace_split"]
    assert rows, "generate() must include whitespace_split rows"
    for row in rows:
        assert row["split"] == gen_adaptive.HELD_OUT, row["id"]


def test_write_rows_writes_canonical_jsonl_per_split(tmp_path: Path) -> None:
    """write_rows(rows, root) creates exactly <root>/<split>/cases.jsonl for the
    splits present, holding that split's rows in generate() order, each line
    byte-equal to json.dumps(row, sort_keys=True) + newline."""
    rows = _rows()
    gen_adaptive.write_rows(rows, tmp_path)
    splits = {row["split"] for row in rows}
    expected_files = {tmp_path / split / "cases.jsonl" for split in splits}
    assert expected_files == set(tmp_path.rglob("cases.jsonl"))
    for split in splits:
        body = (tmp_path / split / "cases.jsonl").read_text(encoding="utf-8")
        assert body.endswith("\n")
        lines = body.splitlines()
        split_rows = [row for row in rows if row["split"] == split]
        assert lines == [json.dumps(row, sort_keys=True) for row in split_rows]
        assert all(line.isascii() for line in lines)
