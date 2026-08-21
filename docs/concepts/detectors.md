# Detectors

A detector receives `SecurityContext` and shared `ContentViews`, then returns zero or more `Finding` objects.

Detectors do not directly block content. This separation makes evidence reusable across policies and keeps detector composition predictable.

V0.1 includes deterministic Unicode, encoding, secret, and context-anomaly detectors plus a bootstrap heuristic injection detector. The heuristic detector exists to exercise the architecture and provide basic utility; it is not a substitute for a calibrated semantic security model.
