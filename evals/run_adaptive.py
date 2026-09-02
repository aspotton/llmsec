"""Adaptive-eval runner (roadmap-08): held-in floors + held-out gaps + FP + gates.

Stdlib only. This is the *adaptive* side of ``evals/AGENTS.md``: it measures the
shipped detectors against the pinned generated mutation ladder under
``evals/adaptive/fixtures`` and reports two honest things -- per-dir held-in
recall floors (regression tripwires, never lowered) and the currently-undetected
held-out rows (published gaps, never hidden). It reuses the fixed-benchmark
scorer ``corpus.score()`` for the recall math, but parses the pinned JSONL rows
directly for the ``split``/``mutation``/``base_id`` metadata that ``EvalCase``
drops (corpus.py:25-32).

Run one case per row through ``Guard.default(diagnostics=True)`` at the untrusted
retrieval boundary and read ``decision.metrics["total_ms"]`` for latency.
``run_rows(guard, cases)`` is the seam the unit tests monkeypatch to inject
actions without the real guard.

Usage (from anywhere):
    PYTHONPATH=src python3 evals/run_adaptive.py [options]

Exit codes: 0 report/tripwire green; 1 on a held-in floor miss, a benign FP
budget breach (fp_rate > --max-benign-fp), a gap REGRESSION vs the BASE-REF
baseline, a missing baseline under ``--gate``, or an invalid ``GIT_BASE_REF``.
Gap regression and baseline-missing apply under ``--gate``; a plain run always
reports (and creates a missing baseline). Latency is report-only unless
``--latency-fail-ms`` is set.
"""

import argparse
import json
import math
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Repo bootstrap idiom (same as run_eval.py): resolve the runtime package and the
# sibling corpus module from the source tree so `python3 evals/run_adaptive.py` works.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from corpus import (  # noqa: E402
    _ALLOWED_ACTIONS,
    EvalCase,
    EvalResult,
    FamilyStats,
    load_corpus,
    score,
)

from llmsec import Guard, Stage, Trust  # noqa: E402

# The pinned snapshot seed (matches gen_adaptive.DEFAULT_SEED) baked into the
# baseline so a --update commit is byte-stable.
SEED = 20260831

# Rows from this dir are the benign FP budget only (expected_block=false); their
# block rate is the FP rate and they are never gaps.
BENIGN_DIR = "benignmutate__handauthored"

# Held-in recall floors keyed by the exact committed <transform>__<family> dir
# names (score() aggregates by dir name, corpus.py:102-112). Every held-in row was
# measured-block at pin time, so each floor is 1.0; a floor that cannot be met is a
# detector regression, never a number to lower. Held-out-only dirs carry no entry.
HELD_IN_FLOORS: dict[str, float] = dict.fromkeys(
    (
        "b64_literal_nest2__secrets_obfuscation",
        "base64_nest2__fake_authority",
        "base64_nest2__instruction_override",
        "base64_nest2__secrets_obfuscation",
        "base64_nest2__system_prompt_extraction",
        "base64_wrap__fake_authority",
        "base64_wrap__instruction_override",
        "base64_wrap__secrets_obfuscation",
        "base64_wrap__system_prompt_extraction",
        "case_flip__fake_authority",
        "case_flip__instruction_override",
        "case_flip__system_prompt_extraction",
        "confusable_fullwidth__fake_authority",
        "confusable_fullwidth__instruction_override",
        "confusable_fullwidth__system_prompt_extraction",
        "hyphen_split__fake_authority",
        "hyphen_split__instruction_override",
        "hyphen_split__system_prompt_extraction",
        "paraphrase_io__fake_authority",
        "paraphrase_io__instruction_override",
        "rot13__fake_authority",
        "rot13__instruction_override",
        "rot13__system_prompt_extraction",
        "secret_zw_in__secrets_obfuscation",
        "secret_zw_text__secrets_obfuscation",
        "whitespace_split__fake_authority",
        "whitespace_split__instruction_override",
        "whitespace_split__system_prompt_extraction",
        "zero_width__fake_authority",
        "zero_width__instruction_override",
        "zero_width__system_prompt_extraction",
    ),
    1.0,
)

_ADAPTIVE = _ROOT / "evals" / "adaptive"
_BASELINE_REL = "evals/adaptive/gap-baseline.json"
_UNDETECTED_HEADER = "| id | mutation | base_id |"


def run_rows(guard: Guard, cases: list[EvalCase]) -> list[EvalResult]:
    """Run every case through the guard at the untrusted retrieval boundary.

    ``metrics["total_ms"]`` (diagnostics=True) is the per-call detector time; the
    tests monkeypatch this function to inject actions without the real guard.
    """

    results: list[EvalResult] = []
    for case in cases:
        decision = guard.inspect(case.text, stage=Stage.RETRIEVAL_DOCUMENT, trust=Trust.UNTRUSTED)
        results.append(
            EvalResult(
                case=case,
                action=decision.action.value,  # blocked == not decision.allowed
                risk=decision.risk,
                total_ms=decision.metrics["total_ms"],
            )
        )
    return results


def _load_meta(corpus_dir: Path) -> dict[str, dict[str, str]]:
    """Parse the pinned JSONL for the fields ``EvalCase`` drops, keyed by row id."""

    meta: dict[str, dict[str, str]] = {}
    for manifest in sorted(corpus_dir.glob("*/cases.jsonl")):
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            meta[str(row["id"])] = {
                "split": str(row.get("split", "held_out")),
                "mutation": str(row.get("mutation", "")),
                "base_id": str(row.get("base_id", "")),
            }
    return meta


def _p95_p99_mean(latency: list[float]) -> tuple[float, float, float]:
    """Nearest-rank p95/p99 plus mean over per-call ``total_ms`` samples."""

    if not latency:
        return 0.0, 0.0, 0.0
    srt = sorted(latency)
    n = len(srt)

    def _rank(quantile: float) -> float:
        return srt[max(0, math.ceil(quantile * n) - 1)]

    return _rank(0.95), _rank(0.99), sum(latency) / n


def _git(repo: Path, *git_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *git_args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )


def _write_baseline(path: Path, gaps: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"seed": SEED, "generated_note": "generated by evals/run_adaptive.py", "gaps": gaps}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_json_gaps(path: Path) -> set[str]:
    return {str(gid) for gid in json.loads(path.read_text(encoding="utf-8"))["gaps"]}


def _resolve_base(
    current_gaps: list[str], *, gate: bool, update: bool, baseline: Path
) -> tuple[set[str] | None, int]:
    """Return (base_gap_ids_or_None_skip, hard_rc); prints the lifecycle marker.

    Precedence: ``--update-gap-baseline`` (the only writer) > ``GIT_BASE_REF``
    (BASE-REF compare, the CI path) > working-tree file. A BASE-REF that predates
    the baseline file bootstraps against the working tree (green for the seed PR);
    a BASE-REF that is not a valid rev is a loud ``GIT_BASE_REF_INVALID``, never a
    silent bootstrap. ``--gate`` with an absent working-tree baseline is a hard
    fail (CI must not invent its own baseline).
    """

    if update:
        _write_baseline(baseline, current_gaps)
        print("GAP_BASELINE_UPDATED")
        return set(current_gaps), 0

    git_ref = os.environ.get("GIT_BASE_REF")
    if git_ref:
        if _git(_ROOT, "cat-file", "-e", f"{git_ref}^{{commit}}").returncode != 0:
            print(f"GIT_BASE_REF_INVALID {git_ref}")
            return None, 1
        show = _git(_ROOT, "show", f"{git_ref}:{_BASELINE_REL}")
        if show.returncode == 0:
            return {str(gid) for gid in json.loads(show.stdout)["gaps"]}, 0
        # Valid commit whose tree predates the baseline file: bootstrap compare the
        # working tree (this is what makes the FIRST PR green), else compare nothing.
        print("GAP_BASELINE_BOOTSTRAP")
        return (_read_json_gaps(baseline) if baseline.is_file() else None), 0

    if baseline.is_file():
        return _read_json_gaps(baseline), 0
    if gate:
        print("GAP_BASELINE_MISSING")
        return None, 1
    _write_baseline(baseline, current_gaps)
    print("GAP_BASELINE_CREATED")
    return set(current_gaps), 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=_ADAPTIVE / "fixtures")
    parser.add_argument("--baseline", type=Path, default=_ADAPTIVE / "gap-baseline.json")
    parser.add_argument("--undetected", type=Path, default=_ADAPTIVE / "UNDETECTED.md")
    parser.add_argument(
        "--out", type=Path, default=_ROOT / "evals" / "results" / "latest_adaptive.json"
    )
    parser.add_argument(
        "--gate", action="store_true", help="CI mode: enforce floors/FP/gap-regression"
    )
    parser.add_argument("--max-benign-fp", type=float, default=0.0)
    parser.add_argument(
        "--latency-fail-ms", type=float, default=None, help="fail if p95 total_ms exceeds this"
    )
    parser.add_argument(
        "--update-gap-baseline", action="store_true", help="rewrite gap-baseline.json from this run"
    )
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"error: corpus directory not found: {args.corpus}", file=sys.stderr)
        return 1
    try:
        cases = load_corpus(args.corpus)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not cases:
        print(f"error: no cases found under {args.corpus}", file=sys.stderr)
        return 1

    meta = _load_meta(args.corpus)
    guard = Guard.default(diagnostics=True)
    results = run_rows(guard, cases)

    all_stats = {s.family: s for s in score(results)}
    held_in_stats = {s.family: s for s in score(_subset(results, meta, "held_in"))}
    held_out_stats = {s.family: s for s in score(_subset(results, meta, "held_out"))}
    gaps = sorted(
        r.case.id
        for r in results
        if r.case.expected_block and r.action in _ALLOWED_ACTIONS  # gap == attack row Allowed
    )

    _print_tables(held_in_stats, held_out_stats)
    _print_benign_and_latency(results)

    _write_undetected(args.undetected, gaps, meta)
    _write_json(args.out, gaps, all_stats, held_in_stats, held_out_stats)

    failures = _floor_failures(held_in_stats, all_stats) + _fp_failures(results, args.max_benign_fp)
    for line in failures:
        print(line)

    base, hard_rc = _resolve_base(
        gaps, gate=args.gate, update=args.update_gap_baseline, baseline=args.baseline
    )
    # A new gap is always reported; only --gate blocks on it (regression = CI red).
    regression = False
    if base is not None:
        new_gaps = sorted(set(gaps) - base)
        if new_gaps:
            print(f"GAP_REGRESSION new={','.join(new_gaps)}")
            regression = bool(args.gate)

    if args.latency_fail_ms is not None:
        p95, _p99, _mean = _p95_p99_mean([r.total_ms for r in results])
        if p95 > args.latency_fail_ms:
            print(f"LATENCY_FAIL p95={p95:.3f}ms > {args.latency_fail_ms:.3f}ms")
            return 1

    return 1 if (failures or regression or hard_rc) else 0


def _subset(
    results: list[EvalResult], meta: dict[str, dict[str, str]], split: str
) -> list[EvalResult]:
    return [r for r in results if meta[r.case.id]["split"] == split]


def _print_tables(
    held_in_stats: dict[str, FamilyStats], held_out_stats: dict[str, FamilyStats]
) -> None:
    print("HELD-IN   (regression tripwires, floors enforced)")
    print(f"{'dir':<44} {'n':>4} {'blocked':>7} {'recall':>8} {'floor':>6}")
    for fam in sorted(HELD_IN_FLOORS):
        stat = held_in_stats.get(fam)
        if stat is None:
            continue
        recall = "n/a" if stat.recall is None else f"{stat.recall:.4f}"
        print(f"{fam:<44} {stat.n:>4} {stat.blocked:>7} {recall:>8} {HELD_IN_FLOORS[fam]:>6.2f}")

    print("\nHELD-OUT  (measured only; published gaps)")
    print(f"{'dir':<44} {'n':>4} {'blocked':>7} {'recall':>8}")
    for fam, stat in sorted(held_out_stats.items()):
        if stat.recall is None:
            continue
        print(f"{fam:<44} {stat.n:>4} {stat.blocked:>7} {stat.recall:>8.4f}")


def _print_benign_and_latency(results: list[EvalResult]) -> None:
    ben = [r for r in results if r.case.family == BENIGN_DIR]
    blocked = sum(1 for r in ben if r.action not in _ALLOWED_ACTIONS)
    fp = blocked / len(ben) if ben else 0.0
    print(f"\nBENIGN-FP  fp_rate={fp:.4f}  ({blocked} blocked / {len(ben)})")

    p95, p99, mean = _p95_p99_mean([r.total_ms for r in results])
    print(f"TOTAL      n={len(results)}  total_ms mean={mean:.3f} p95={p95:.3f} p99={p99:.3f}")


def _floor_failures(
    held_in_stats: dict[str, FamilyStats], all_stats: dict[str, FamilyStats]
) -> list[str]:
    failures: list[str] = []
    for fam, floor in sorted(HELD_IN_FLOORS.items()):
        if fam not in all_stats:  # dir absent from this corpus: nothing to measure
            continue
        stat = held_in_stats.get(fam)
        measured = None if stat is None else stat.recall
        if measured is None or measured < floor:
            shown = "n/a" if measured is None else f"{measured:.4f}"
            failures.append(f"BASELINE_FAIL {fam} {shown}")
    return failures


def _fp_failures(results: list[EvalResult], max_fp: float) -> list[str]:
    ben = [r for r in results if r.case.family == BENIGN_DIR]
    blocked = sum(1 for r in ben if r.action not in _ALLOWED_ACTIONS)
    fp = blocked / len(ben) if ben else 0.0
    if fp > max_fp:
        return [f"BENIGN_FP {fp:.4f} > {max_fp:.4f} ({blocked} blocked / {len(ben)})"]
    return []


def _write_undetected(path: Path, gaps: list[str], meta: dict[str, dict[str, str]]) -> None:
    """Regenerate the published gap table: one row per currently-ALLOWed attack row."""

    lines = [_UNDETECTED_HEADER, "| --- | --- | --- |"]
    lines += [f"| {gid} | {meta[gid]['mutation']} | {meta[gid]['base_id']} |" for gid in gaps]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_json(
    path: Path,
    gaps: list[str],
    all_stats: dict[str, object],
    held_in_stats: dict[str, object],
    held_out_stats: dict[str, object],
) -> None:
    def _dump(stats: dict[str, object]) -> list[dict[str, object]]:
        return [
            {
                "family": s.family,
                "n": s.n,
                "blocked": s.blocked,
                "recall": s.recall,
                "fp_rate": s.fp_rate,
            }
            for s in (stats[k] for k in sorted(stats))
        ]

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "guard": "default",
        "seed": SEED,
        "rows": _dump(all_stats),
        "held_in": _dump(held_in_stats),
        "held_out": _dump(held_out_stats),
        "gaps": gaps,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
