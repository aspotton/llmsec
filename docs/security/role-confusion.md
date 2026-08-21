# Role confusion

Recent research frames prompt injection partly as role confusion: models may infer who produced text from its style rather than reliably respecting application-level role boundaries.

The architectural consequence for llmsec is important: security authority must not live only in natural-language role labels. Provenance, principal, trust, authority, capabilities, and approval state belong in host-controlled data structures outside the model's ability to rewrite.

Future model work will include explicit role-impersonation signals and a separate trusted-metadata path rather than relying solely on textual tags such as `[TRUST=UNTRUSTED]`.
