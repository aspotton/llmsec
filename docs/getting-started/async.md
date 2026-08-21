# Async usage

Use `await guard.ainspect(...)` inside async applications.

The synchronous `inspect()` method uses `asyncio.run()` and therefore refuses to run inside an active event loop. This is intentional: callers should not hide nested loop behavior in server code.
