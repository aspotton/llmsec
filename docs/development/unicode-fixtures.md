# Unicode fixtures and source-code conventions

`llmsec` intentionally handles adversarial Unicode, including confusable characters, full-width forms, zero-width characters, bidirectional controls, Unicode tag characters, combining marks, and variation selectors. Tests and evaluation data therefore need to represent characters that linters and reviewers are normally right to treat as suspicious.

## Source-code rule

When a non-ASCII character is security-relevant because of its code point or invisibility, prefer an explicit Unicode escape or numeric code-point construction in Python source instead of pasting the literal character.

For example, prefer:

```python
raw = "\uff21\uff22\uff23"  # FULLWIDTH LATIN CAPITAL LETTERS A, B, C
zero_width_space = "\u200b"
bidi_override = "\u202e"
```

over:

```python
raw = "ＡＢＣ"
```

This keeps the source auditable, avoids visually ambiguous or invisible characters in code review, and prevents lint rules such as Ruff `RUF001` from flagging intentional fixtures.

## Comments and naming

For security-sensitive Unicode fixtures:

- Prefer named variables over unexplained inline escape sequences.
- Add a short comment naming the character or attack mechanism when the code point is not obvious.
- Use uppercase hexadecimal digits consistently for code points when practical.
- Keep expected human-readable normalized output as ordinary text when it is unambiguous.
- Do not disable ambiguous-Unicode lint rules globally just to accommodate security fixtures.

Example:

```python
def test_nfkc_normalization_is_available_without_mutating_raw() -> None:
    raw = "\uff21\uff22\uff23"  # Full-width A, B, C.

    views = build_content_views(raw)

    assert views.raw == raw
    assert views.nfkc == "ABC"
```

## Test vectors and datasets

Large adversarial corpora may store literal Unicode in data files when literal bytes/code points are part of the fixture. In that case:

- keep the file encoding explicit and documented;
- record or document the intended code points/transformations;
- avoid copying invisible or confusable characters into Python source merely for convenience;
- preserve raw fixture bytes when byte-level behavior is under test;
- verify that normalization tests assert both the unchanged raw view and the expected derived view.

For JSON/JSONL fixtures, escaped forms are preferred when they make code points easier to audit. If literal forms are required to reproduce a real payload, document that choice in the fixture metadata or nearby documentation.

## Runtime code

The same rule applies to detector constants. Prefer explicit escapes, ranges, Unicode categories, or `ord()`/`chr()`-based construction over visually ambiguous literals. Security behavior should be understandable from a plain-text diff.

## Linting

Ruff's ambiguous-Unicode checks are intentionally enabled. Treat a `RUF001`, `RUF002`, or `RUF003` finding as a prompt to make the security intent clearer rather than as a reason to weaken lint configuration.

If a literal character is genuinely necessary and an escape would change the thing being tested, use the narrowest possible per-line suppression and explain why in a comment. This should be exceptional.
