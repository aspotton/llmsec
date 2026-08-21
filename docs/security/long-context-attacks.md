# Long-context attacks

An attack can be fragmented across context windows so that no single small classifier window looks malicious while the downstream model reconstructs the complete intent.

V0.1 does not claim protection against this class. Planned work includes window embeddings, a lightweight global aggregator, suspicious-fragment reconstruction, and RAG ingestion/query-time separation.
