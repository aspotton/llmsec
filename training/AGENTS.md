# Training instructions for coding agents

Training code is intentionally outside the production package.

Before adding model training:

- record dataset source, immutable revision, license, collection date, and transformation history;
- separate train/validation/test data by source, semantic family, and attack transformation where appropriate;
- prevent public evaluation sets from silently leaking into training;
- preserve benign hard negatives, not just attack examples;
- do not automatically train on raw production feedback;
- keep reproducible configs and export steps;
- produce ONNX or another safe runtime artifact rather than requiring Python object deserialization in production;
- preserve the exact transformation recipe/code points for Unicode adversarial examples, and prefer escaped/auditable representations in Python source.

Read:

- `docs/roadmap/07-custom-security-model.md`
- `docs/development/dataset-governance.md`
- `docs/security/evaluation-philosophy.md`
- `docs/development/unicode-fixtures.md`
