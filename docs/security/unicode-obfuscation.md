# Unicode and character obfuscation

Character-level transformations can preserve meaning for the downstream LLM while changing what a detector sees.

V0.1 flags selected zero-width characters, bidirectional controls, Unicode tag characters, and supplementary variation selectors. It also exposes normalized content views without replacing the raw source.

Future work expands confusable analysis, Unicode-tag decoding, markup-aware hidden text, reversible span mapping, and adversarial training over character transformations.


## Repository fixture convention

Because the project intentionally tests characters that may be invisible or visually confusable, Python source should normally encode those characters using explicit Unicode escapes or code-point construction. This is a source-code auditability convention, not a runtime normalization rule: the runtime must continue to inspect and preserve the actual raw Unicode content it receives.

See [`../development/unicode-fixtures.md`](../development/unicode-fixtures.md).
