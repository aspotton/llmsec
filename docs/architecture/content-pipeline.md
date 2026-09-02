# Content pipeline

The content pipeline produces immutable representations reused by detectors.

V0.1 exposes:

- raw source text;
- NFKC-normalized text;
- a view with selected invisible controls removed (including the invisible-operator family U+2061-U+2064);
- bounded decode candidates: printable Base64 flattened breadth-first to depth 2, plus a ROT13 candidate gated by length/shape so random text is not decoded.

Normalization never replaces the authoritative source text. Detectors can compare views and report evidence while preserving the original content.

Future work may add span mapping, markup/HTML extraction, confusable-character skeletons, Unicode-tag decoding, percent/hex/entity decoding, and tokenizer/model inputs. All decoders must remain size- and depth-bounded to prevent the guardrail itself from becoming a denial-of-service target.
