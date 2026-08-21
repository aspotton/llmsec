# Guard

`Guard` is the main public entry point.

```python
from llmsec import Guard

guard = Guard.default()
result = guard.inspect_user_input("hello")
```

Use `ainspect()` and the async convenience methods in applications that already run an event loop.

`Guard` owns detector configuration and policy. It does not make network calls or download model artifacts in V0.1.
