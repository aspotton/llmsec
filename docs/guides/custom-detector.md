# Custom detectors

A custom detector can be implemented as a class following the detector protocol or with the `@detector` helper.

```python
from llmsec import Finding, Severity, Stage, detector


@detector(name="internal_project", stages=frozenset({Stage.MODEL_OUTPUT}))
async def internal_project(context, views):
    if "PROJECT PHOENIX" not in views.raw:
        return []
    return [
        Finding(
            detector="internal_project",
            category="internal_information",
            confidence=1.0,
            severity=Severity.HIGH,
            message="Internal project name detected.",
        )
    ]
```

Then register it with `guard.add_detector(internal_project)`.

Custom detectors should return evidence, not policy decisions.
