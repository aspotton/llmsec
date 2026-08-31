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

## Profiles

`Guard.from_profile(profile)` selects a preset `DefaultPolicy` tuned for an application shape:

```python
from llmsec import Guard, Profile

guard = Guard.from_profile(Profile.AGENT)
```

| Profile | `confirm_threshold` | `block_threshold` | Intent |
| --- | --- | --- | --- |
| `Profile.CHAT` | 0.75 | 0.90 | Untuned defaults; same policy as `Guard.default()`. |
| `Profile.RAG` | 0.80 | 0.88 | Retrieval content: confirm band before a lower block bar. |
| `Profile.AGENT` | 0.85 | 0.85 | Agentic tool use: widest CONFIRM band, lowest block bar. |

The CLI applies the same presets: `llmsec scan --profile <chat|rag|agent>` (omit for the chat/defaults policy).

Profiles change policy thresholds only. The detector set is identical to `Guard.default()` for every profile; `Guard.default(policy=...)` accepts an explicit `DefaultPolicy` override.
