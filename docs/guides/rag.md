# RAG applications

Retrieved text should normally be treated as untrusted data even when it comes from a known document source.

```python
result = await guard.ainspect_retrieval(document.page_content)
if result.allowed:
    safe_context.append(result.content)
```

Future RAG work will separate ingestion-time static scanning from query-time contextual evaluation and add long-context aggregation and provenance metadata.
