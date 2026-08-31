"""Static eval corpus primitives: loader + scorer. Stdlib only, no runner IO.

This is the fixed-benchmark side of `evals/AGENTS.md`: it measures today's
regex-heuristic detectors against a static pattern vocabulary, so its recall
numbers are a regression tripwire for future changes, NOT evidence of
adversarial robustness (adaptive evals live on the roadmap-08 track).
"""

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# Repo bootstrap idiom so un-installed execution (`python3 evals/corpus.py`) and
# importers of this module resolve the runtime package from the source tree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# DecisionAction values that do NOT count as blocked (mirrors Decision.allowed:
# ALLOW/SANITIZE pass, BLOCK/CONFIRM do not). Stored as strings so the scorer
# stays decoupled from the runtime Decision type.
_ALLOWED_ACTIONS = frozenset({"allow", "sanitize"})


@dataclass(frozen=True)
class EvalCase:
    """One labeled case; `family` is the fixture directory name, not in the row."""

    id: str
    family: str
    expected_block: bool
    text: str


@dataclass
class EvalResult:
    """Outcome of running one case through a Guard (action kept as a plain str)."""

    case: EvalCase
    action: str
    risk: float
    total_ms: float


@dataclass(frozen=True)
class FamilyStats:
    """Per-family aggregate. `recall` is None when n == 0 (no cases to divide by);
    `fp_rate` is meaningful for the benign family (blocked / n), 0.0 elsewhere."""

    family: str
    n: int
    blocked: int
    recall: float | None
    fp_rate: float


def load_corpus(corpus_dir: Path) -> list[EvalCase]:
    """Load `<corpus_dir>/*/cases.jsonl`; the child directory name is the family."""

    cases: list[EvalCase] = []
    for manifest in sorted(corpus_dir.glob("*/cases.jsonl")):
        family = manifest.parent.name
        for lineno, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSON in {manifest} at line {lineno}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"row is not a JSON object in {manifest} at line {lineno}")
            missing = {"id", "expected_block", "text"} - row.keys()
            if missing:
                raise ValueError(
                    f"row missing keys {sorted(missing)} in {manifest} at line {lineno}"
                )
            cases.append(
                EvalCase(
                    id=str(row["id"]),
                    family=family,
                    expected_block=bool(row["expected_block"]),
                    text=str(row["text"]),
                )
            )
    return cases


def score(results: list[EvalResult]) -> list[FamilyStats]:
    """Aggregate results per family, sorted by family name.

    recall = blocked / n over the whole family (families are label-uniform in
    this corpus; for the benign family that quantity is reported via fp_rate
    instead), None when the family has no cases. fp_rate counts blocked
    decisions among cases whose expected_block is False.
    """

    by_family: dict[str, list[EvalResult]] = {}
    for result in results:
        by_family.setdefault(result.case.family, []).append(result)

    stats: list[FamilyStats] = []
    for family in sorted(by_family):
        rows = by_family[family]
        n = len(rows)
        blocked_rows = [
            row
            for row in rows
            if row.action not in _ALLOWED_ACTIONS  # blocked == not decision.allowed
        ]
        recall = len(blocked_rows) / n if n else None
        fp_rows = [row for row in blocked_rows if not row.case.expected_block]
        stats.append(
            FamilyStats(
                family=family,
                n=n,
                blocked=len(blocked_rows),
                recall=recall,
                fp_rate=len(fp_rows) / n if n else 0.0,
            )
        )
    return stats


if __name__ == "__main__":
    corpus = load_corpus(Path(__file__).resolve().parent / "fixtures")
    counts = Counter(case.family for case in corpus)
    for family in sorted(counts):
        print(f"{family}: {counts[family]}")
    print(f"total: {len(corpus)}")
