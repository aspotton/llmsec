# Adaptive evaluation corpus (generated)

This is the **adaptive** side required by [evals/AGENTS.md](../AGENTS.md) and
roadmap [08-adaptive-evaluation](../../docs/roadmap/08-adaptive-evaluation.md):
a pinned, deterministically *generated* attack corpus that sits next to — and
stays separate from — the fixed static benchmark in [`evals/fixtures`](../fixtures/README.md).
Nothing here is hand-written fixture data; every row is reproducible from the
fixed attack bases via the seeded mutation ladder in
[`mutations.py`](../mutations.py).

## Layout

```text
evals/adaptive/
  README.md
  fixtures/<transform>__<source_family>/cases.jsonl   # generated, pinned by seed
  fixtures/benignmutate__handauthored/cases.jsonl     # generated benign-FP-budget rows
  fixtures/b64_literal_nest2__<family>/cases.jsonl    # nesting over a base that already embeds a base64 literal
  fixtures/base64_hint_miss__<family>/cases.jsonl     # hint-less base64_wrap routings (normally empty; mutations._payload prevents it)
```

One `cases.jsonl` per *dir key*, never per split: the dir key is
`<transform>__<source_family>` (row routing lives in `gen_adaptive.dir_key`),
never a bare fixed-family name. Each line is the canonical record
`json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":"))`,
keys exactly `{id, expected_block, text, mutation, base_id, split}`.

## Measured split semantics

`split` is not a prediction; it is assigned **by running today's
`Guard.default(diagnostics=True)` over every row at generation time**
(`Stage.RETRIEVAL_DOCUMENT` / `Trust.UNTRUSTED`):

- `held_in` — the guard *measured-blocked* the row. These are regression
  tripwires: if a future detector change lets one through, the fixed-vs-adaptive
  comparison shows a real regression.
- `held_out` — the guard *measured-Allowed* the row. These are published
  detection gaps. After the gap-closure work the only remaining gap family is
  `paraphrase_io` (semantic synonym substitution, 31 rows); the transformation
  gaps `base64_nest2`, `rot13`, `whitespace_split`, `hyphen_split`, and
  `secret_zw_in` are closed and their rows are now `held_in`.

`mutations.SPLIT` is only the static prior the measurement validates. Two drift
guards abort generation rather than emit a lying corpus:

1. a row the static registry expected to self-block that the guard now Allows
   (mislabel), and
2. a `benignmutate` row the guard now blocks (benign FP budget).

## Row sources

- **Attack rows**: every `expected_block=True` fixture in `evals/fixtures`,
  expanded by `mutations.generate_mutations(bases, seed)` (348 rows: text
  transforms over the 3 text families, base64 transforms over all 4, and the
  secret-zw transforms over the 6 secret bases).
- **`benignmutate__handauthored`**: the 6 benign fixtures whose text contains
  attack-adjacent detector vocabulary (`system prompt`, `disregard`, `Forget`,
  `Repeat`, `Dump`, `Secret...`), lightly perturbed with the `whitespace_split`
  transform and labeled `mutation="benignmutate"`, `expected_block=False`.
  `whitespace_split` is used deliberately: it measured ALLOW on all 6 rows, so
  these rows stay pure false-positive budget (the zero-width `U+200B` variant
  measured BLOCK on all 6 and would poison the FP budget). They are `held_out`
  (measured-Allow) and the generator aborts if the guard ever blocks one.
- **`b64_literal_nest2__<family>`**: the `base64_nest2` rows whose base already
  embeds a base64 literal (`mutations._BASE64_LITERAL_RE` match). This is the
  simplified routing that replaces the planned per-base `b64_literal_rot13`
  special-casing: the row itself is still the double-wrap, now caught by the
  depth-2 Base64 flattening and so `held_in`.

## Seed / pin model

`generate(seed)` is a pure function of `seed` over the fixed corpus: same seed +
same fixtures + same detectors ⇒ byte-identical rows and splits. The corpus
committed under `fixtures/` is pinned by the seed recorded in the generator
(`DEFAULT_SEED = 20260831`) plus a regen byte-check. As detectors improve, the
*split* of the same rows moves from `held_out` to `held_in`; that migration, not
the raw row count, is the progress signal this track is meant to show.

## Regenerating

```bash
PYTHONPATH=src python3 evals/gen_adaptive.py                  # write evals/adaptive/fixtures
PYTHONPATH=src python3 evals/gen_adaptive.py --seed N        # explicit seed
PYTHONPATH=src python3 evals/gen_adaptive.py --regenerate    # byte-compare, exit 1 on drift
```

`--regenerate` writes nothing: it rebuilds the rows in memory, byte-compares
every file under `fixtures/` (missing or extra files count as drift), prints a
unified diff per drifted file, and exits 0 only on an exact match ("byte-match").

A passing corpus is a *transformation-coverage* measurement, not a robustness
proof: never treat a random split of transformed copies as adversarial
robustness ([evals/AGENTS.md](../../evals/AGENTS.md)).
