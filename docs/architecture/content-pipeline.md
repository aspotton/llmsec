# Content pipeline

The content pipeline produces immutable representations reused by detectors.

V0.1 exposes:

- raw source text;
- NFKC-normalized text;
- a view with selected invisible controls removed;
- bounded printable Base64 decode candidates.

Normalization never replaces the authoritative source text. Detectors can compare views and report evidence while preserving the original content.

Future work may add span mapping, markup/HTML extraction, confusable-character skeletons, Unicode-tag decoding, percent/hex/entity decoding, and tokenizer/model inputs. All decoders must remain size- and depth-bounded to prevent the guardrail itself from becoming a denial-of-service target.
