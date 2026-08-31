# Evaluation workspace

This directory holds the fixed benchmark corpus and its tripwire runner. It is the fixed benchmark from [AGENTS.md](AGENTS.md), not an adaptive evaluation: no transformation sweeps, no held-out families, no model-quality or latency scoring. Those live under roadmap [08-adaptive-evaluation](../docs/roadmap/08-adaptive-evaluation.md).

## Layout

```text
evals/
  corpus.py            loader + scorer primitives (PYTHONPATH=src python3 evals/corpus.py prints per-family counts)
  run_eval.py          stdlib CLI runner: fixed-width table + JSON dump + baseline exit code
  fixtures/*/cases.jsonl   attack-family and benign cases (see fixtures/README.md)
  results/             gitignored run artifacts (latest.json)
```

## Running

```bash
PYTHONPATH=src python3 evals/corpus.py      # per-family counts (total 54)
PYTHONPATH=src python3 evals/run_eval.py    # run corpus through Guard.default(), exit 0 on baseline
```

`run_eval.py` inspects every case at `Stage.RETRIEVAL_DOCUMENT` with `Trust.UNTRUSTED` and prints per-family `recall` plus a benign `fp_rate`. Only the families listed in `ASSERTED_BASELINES` (mirroring `tests/unit/test_eval_scorer.py`) can fail the run; every other family is printed as `measured-only`. Current measured values: `instruction_override`, `system_prompt_extraction` and `fake_authority` 12/12, `secrets_obfuscation` 6/6, benign `fp_rate` 0.0.

A passing run is a tripwire, not a robustness claim: it means the shipped detectors still catch a small static corpus under one fixed profile. It says nothing about unseen transformations or held-out families. The `measured-only` families carry no floor here, and detection gaps are recorded in [docs/security/limitations.md](../docs/security/limitations.md); if calibration ever produces a genuinely undetected case it is exported to `fixtures/UNDETECTED.md` (see [fixtures/README.md](fixtures/README.md)), never silently dropped.
