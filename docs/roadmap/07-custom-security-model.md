# Project-trained security model

Train a compact local model after the runtime/evaluation abstractions are stable.

Candidate architecture:

- small semantic encoder;
- lightweight raw-byte/character branch for obfuscation signals;
- multi-label heads for direct/indirect injection, role impersonation, fake authorization, exfiltration, tool manipulation, and obfuscation;
- span/evidence head;
- uncertainty/OOD signal;
- trusted stage/provenance/authority metadata fused through a separate feature path rather than only textual tags.

Export an INT8 ONNX artifact for the default runtime. Keep PyTorch/Transformers in training only.
