# Adaptive evaluation

Build an evaluation lab that assumes attackers adapt to the released defense.

Include character/Unicode transformations, semantic attacks, role-confusion attacks, long-context fragmentation, multi-turn attacks, tool-result injection, memory manipulation, held-out families, and attacks optimized against candidate models.

Release gates should include false-positive budgets and latency/utility requirements as well as attack recall.

## Status

Shipped: the text-detector mutation ladder. A seeded generator (`evals/gen_adaptive.py`,
`evals/mutations.py`) expands the fixed attack bases with deterministic character/encoding
transforms into a pinned corpus, split by measurement into held-in regression tripwires and
held-out published gaps, and `evals/run_adaptive.py --gate` enforces recall floors, a benign
false-positive budget, and gap regression in CI.

Still open: agent-level evaluation. Multi-turn attacks, memory manipulation, tool-result
injection, and long-context fragmentation are unmeasured, as are attacks optimized against
candidate models. The ladder covers text detectors only; unauthorized-effect and task-utility
measurement per `evals/AGENTS.md` has no harness yet.
