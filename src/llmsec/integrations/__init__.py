"""Framework integrations for llmsec.

Submodules adapt llmsec to third-party LLM client surfaces. They are lazy by
design: importing this package imports nothing, and no submodule may import an
SDK. Import a specific integration (e.g. ``llmsec.integrations.openai_compat``)
to get its adapters.
"""
