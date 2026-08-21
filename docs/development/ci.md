# Continuous integration

GitHub Actions runs on pushes and pull requests.

The primary workflow performs lint, formatting checks, type checks, package installation/build sanity, and the test suite across supported Python versions. A dedicated fast security-regression workflow runs `tests/security/` independently so security coverage remains visible.

As model and evaluation code is added, expensive adaptive/latency suites should move to nightly or release-candidate workflows while fast correctness and security checks continue to gate every push/PR.
