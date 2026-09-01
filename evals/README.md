# Evaluation workspace

This directory holds the fixed benchmark corpus and its tripwire runner, plus the adaptive mutation-ladder track. The fixed side is the benchmark from [AGENTS.md](AGENTS.md): no transformation sweeps, no held-out families, no model-quality or latency scoring. Per `evals/AGENTS.md`: "Keep fixed benchmark results separate from adaptive attack results." so the two runners, corpora, and reports below never mix; adaptive evaluation is roadmap [08-adaptive-evaluation](../docs/roadmap/08-adaptive-evaluation.md).

## Layout

```text
evals/
  corpus.py            loader + scorer primitives (PYTHONPATH=src python3 evals/corpus.py prints per-family counts)
  run_eval.py          stdlib CLI runner: fixed-width table + JSON dump + baseline exit code
  fixtures/*/cases.jsonl   attack-family and benign cases (see fixtures/README.md)
  gen_adaptive.py      seeded generator for the adaptive mutation corpus (+ --regenerate byte-check)
  mutations.py         deterministic transform ladder over the fixed attack bases
  run_adaptive.py      adaptive runner: held-in floors + FP budget + gap-regression gate
  adaptive/            generated corpus, pinned at seed 20260831 (see adaptive/README.md)
  adaptive/UNDETECTED.md   published held-out gaps (pipe table, lockstep with gap-baseline.json)
  adaptive/gap-baseline.json  gap set at the base ref, for the regression gate
  results/             gitignored run artifacts (latest.json, latest_adaptive.json)
```

## Running

```bash
PYTHONPATH=src python3 evals/corpus.py            # per-family counts (total 54)
PYTHONPATH=src python3 evals/run_eval.py          # run corpus through Guard.default(), exit 0 on baseline
PYTHONPATH=src python3 evals/run_adaptive.py      # adaptive report (measured-only)
PYTHONPATH=src python3 evals/run_adaptive.py --gate  # adaptive CI gate
```

`run_eval.py` inspects every case at `Stage.RETRIEVAL_DOCUMENT` with `Trust.UNTRUSTED` and prints per-family `recall` plus a benign `fp_rate`. Only the families listed in `ASSERTED_BASELINES` (mirroring `tests/unit/test_eval_scorer.py`) can fail the run; every other family is printed as `measured-only`. Current measured values: `instruction_override`, `system_prompt_extraction` and `fake_authority` 12/12, `secrets_obfuscation` 6/6, benign `fp_rate` 0.0.

A passing run is a tripwire, not a robustness claim: it means the shipped detectors still catch a small static corpus under one fixed profile. It says nothing about unseen transformations or held-out families. The `measured-only` families carry no floor here, and detection gaps are recorded in [docs/security/limitations.md](../docs/security/limitations.md); if calibration ever produces a genuinely undetected case it is exported to `fixtures/UNDETECTED.md` (see [fixtures/README.md](fixtures/README.md)), never silently dropped.

`run_adaptive.py` is the separate adaptive runner: it scores the pinned generated mutation corpus under `adaptive/` through the same scorer primitives and reports measured held-in recall (floors 1.0, never lowered) plus published held-out gaps. Its results are transformation-coverage measurements on generated copies, never fixed-benchmark scores, and they stay out of the tables above. A green adaptive gate means no detector regression and no *new* gaps relative to the base ref, not adversarial robustness. See [adaptive/README.md](adaptive/README.md) and [docs/development/testing.md](../docs/development/testing.md).
