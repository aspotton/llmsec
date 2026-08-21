# Dataset governance

Future training data should have machine-readable manifests containing source, immutable revision, license, collection date, transformations, split policy, and redistribution status.

Raw production reports must never flow automatically into training. Community attack submissions should be isolated, deduplicated, reviewed, and accompanied by benign counterparts where possible.

Train/eval splits should group semantic families, source ancestry, and transformation chains to reduce contamination.
