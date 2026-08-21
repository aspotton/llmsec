# Indirect prompt injection

Indirect injection enters through data the application retrieves or a tool returns rather than through the user's direct message.

Examples include malicious instructions inside web pages, emails, documents, API responses, and memory entries.

V0.1 represents retrieval and tool-result locations using typed stages so policies and future models can distinguish these contexts. Future enforcement will also restrict which values untrusted sources may influence in proposed actions.
