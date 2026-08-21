# Security Policy

llmsec is security-sensitive software. Please avoid publicly disclosing a bypass that could enable real-world compromise before maintainers have had a reasonable opportunity to investigate.

When reporting an issue, include:

- affected version or commit;
- minimal reproducer;
- expected and observed decision;
- relevant stage and trust context;
- whether the issue affects only detection or can cause an unauthorized action in an integration;
- a benign counterpart when possible, so fixes can be evaluated for overblocking.

The project does not claim that prompt-injection detection is complete. The threat model intentionally assumes detectors can fail; future action-enforcement layers are designed around that assumption.
