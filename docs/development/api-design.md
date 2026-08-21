# API design

Public Python APIs prefer typed security primitives over free-form string identifiers.

Use:

```python
stage = Stage.RETRIEVAL_DOCUMENT
trust = Trust.UNTRUSTED
```

rather than accepting arbitrary values throughout the runtime. Serialization/configuration boundaries may use strings, but those values must be validated and converted immediately.

Keep the common path simple through convenience methods such as `inspect_retrieval()` while preserving the explicit generic API for advanced integrations.
