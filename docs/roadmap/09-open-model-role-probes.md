# Open-model role probes

Experimental future work for locally hosted/open-weight models may inspect hidden-state signals during prefill to estimate role confusion before generation.

This is optional defense-in-depth, not a portable core dependency. It should be implemented only where the inference backend exposes suitable activations without requiring a second expensive model pass.
