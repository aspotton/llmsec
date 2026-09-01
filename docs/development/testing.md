# Testing

The test hierarchy separates ordinary correctness from security regressions.

```text
tests/unit/         small behavior tests
tests/integration/  public API and composition tests
tests/security/     fast known-attack regressions
```

Run locally:

```bash
pytest
pytest -m security
```

Every bug fix should add a regression test. New detectors should include positive cases and benign negatives. Security-sensitive changes should demonstrate the old failure mode where practical.

Larger adaptive/model evaluations belong under `evals/` so every commit does not require an expensive benchmark run.

The `evals/` workspace now has a first working piece: a fixed static corpus under `evals/fixtures/` and a stdlib runner, `PYTHONPATH=src python3 evals/run_eval.py`. It scores every case through `Guard.default()` and fails (exit 1) only when an asserted family drops below its recall floor or the benign false-positive rate exceeds `--max-benign-fp`; everything else is printed measured-only. See [`evals/README.md`](../../evals/README.md) for what the numbers do and do not claim. This is a fixed-benchmark tripwire, not adaptive robustness evidence; adaptive evals are roadmap item [08](../roadmap/08-adaptive-evaluation.md).

## Adaptive evaluation (roadmap 08)

The adaptive track measures the shipped detectors against a deterministically generated mutation ladder over the fixed attack bases, under `evals/adaptive/`. Generate, verify, and run it with:

```bash
PYTHONPATH=src python3 evals/gen_adaptive.py                  # write the pinned corpus
PYTHONPATH=src python3 evals/gen_adaptive.py --regenerate     # byte-compare, exit 1 on drift
PYTHONPATH=src python3 evals/run_adaptive.py                  # report-only
PYTHONPATH=src python3 evals/run_adaptive.py --gate           # CI mode (security-regression workflow)
```

`--gate` enforces the held-in recall floors, the benign FP budget (`--max-benign-fp`, default 0.0), and gap regression against `evals/adaptive/gap-baseline.json` (`--update-gap-baseline` rewrites that file from an intentional run). Gap-regression and missing-baseline checks need `GIT_BASE_REF`, which the workflow resolves from `GITHUB_BASE_REF`.

**Held-in vs held-out** is a measured split, not a guess: at generation time every row runs through today's `Guard.default(diagnostics=True)`; rows the guard blocked are `held_in` regression tripwires (206 rows, each dir's floor is 1.0), and rows it allowed are `held_out` published gaps (148 rows, 142 of them in the gap baseline; the rest are the benign FP-budget rows, which are never gaps). As detectors improve, rows migrate from held-out to held-in; that migration is the progress signal.

**Never-lower-floors rule:** a held-in floor miss is a detector regression, never a number to edit. Fix the detector or justify the change; do not touch `HELD_IN_FLOORS`.

**Seed/pin model:** the corpus is a pure function of seed `20260831` over the fixed fixtures (354 rows, 33 directories), committed byte-stable. `gen_adaptive --regenerate` is the drift check and runs in the `ci.yml` **Python 3.13** leg, because `unicodedata` version differences across interpreters can change mutated bytes; other interpreters may legitimately report drift.

**Latency:** `run_adaptive` reports per-run `total_ms` and is report-only unless `--latency-fail-ms` is set. Measured baseline (`.omo/evidence/adaptive-evals/latency-baseline.txt`, Python 3.11.0rc1, Linux x86_64, 2026-08-31, 3 passes over the 354-row corpus): means 0.116/0.121/0.118 ms, p95 0.154/0.159/0.157 ms (median p95 0.157 ms), p99 0.194-0.198 ms. So measured p95 is roughly 0.16 ms per run. Keep the gate report-only until a human reads these numbers and passes `--latency-fail-ms` deliberately; CI runs 3.13, so re-measure there before setting a threshold.

What this track claims: a regression tripwire over transformation mutations plus honest gap publication (`evals/adaptive/UNDETECTED.md`). It is **not** adversarial robustness evidence. Agent-level evaluation, multi-turn, memory, tool-result, and long-context attacks remain open roadmap-08 work; see [evals/adaptive/README.md](../../evals/adaptive/README.md).


## Adversarial Unicode fixtures

Unicode security tests are expected to exercise confusable, full-width, zero-width, bidirectional, tag, combining, and variation-selector characters. In Python source, represent security-relevant or visually ambiguous characters with explicit Unicode escapes or code-point construction rather than pasting the literal glyph. This keeps diffs auditable and preserves Ruff's ambiguous-Unicode checks as a useful safeguard.

See [`unicode-fixtures.md`](unicode-fixtures.md) for the project-wide convention, including the narrow exception for fixtures that must preserve exact literal bytes/code points.
