# Configuration

V0.1 favors Python configuration over a large declarative schema.

```python
from llmsec import Guard
from llmsec.detectors import UnicodeDetector
from llmsec.policy import DefaultPolicy

guard = Guard(
    detectors=[UnicodeDetector()],
    policy=DefaultPolicy(block_threshold=0.95),
)
```

A validated YAML/JSON configuration layer is planned after the public policy model stabilizes. String values at serialization boundaries will be converted into typed runtime values immediately.
