from dataclasses import dataclass

from llmsec.core.enums import Stage, Trust


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Trusted application metadata supplied outside inspected natural-language content."""

    stage: Stage = Stage.USER_INPUT
    trust: Trust = Trust.UNKNOWN
