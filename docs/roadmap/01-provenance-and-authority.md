# Provenance and authority

Add first-class `Principal`, `Provenance`, `Authority`, and richer trust concepts to `SecurityContext`/events.

Key invariant: content cannot upgrade its own authority by claiming to be a system message, user approval, internal reasoning, or trusted tool output.

Authority should be scoped (for example data, user intent, application policy, approval) rather than represented as one numeric hierarchy.
