# Execution model

`Guard.ainspect()` is the primary composable inspection API. `Guard.inspect()` is a synchronous convenience wrapper and intentionally refuses to run inside an already-active event loop.

Content views are built once. Detectors that apply to the active `Stage` are then scheduled concurrently. Each detector declares its expected cost and timeout through `DetectorSpec`.

V0.1 detectors are small and local. Future CPU-bound model inference should run through a bounded executor or native runtime rather than blocking the event loop under high concurrency.

Diagnostics are opt-in because observability itself should not impose unnecessary hot-path cost.
