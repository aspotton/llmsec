# Content views

`ContentViews` prevents every detector from independently repeating normalization and decoding work.

The raw source is retained unchanged. Derived views are immutable and bounded. This supports low latency, reproducibility, and future span-level evidence mapping.
