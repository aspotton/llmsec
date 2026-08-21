# Detector instructions for coding agents

This directory contains detection logic only.

Requirements for new detectors:

- Implement the detector protocol and declare a `DetectorSpec`.
- Return `Finding` objects; do not return or encode policy decisions.
- Do not mutate content.
- Reuse `ContentViews` and existing preprocessing.
- Bound work by input size and declare a sensible timeout.
- Avoid network calls in default detectors.
- Include positive, benign-negative, and adversarial regression tests.
- Document known false positives and false negatives for substantive detectors.

Read:

- `docs/concepts/detectors.md`
- `docs/development/adding-a-detector.md`
- `docs/security/limitations.md`
