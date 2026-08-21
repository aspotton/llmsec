from collections.abc import Mapping
from dataclasses import dataclass, field

from llmsec.core.enums import Severity

Span = tuple[int, int]


@dataclass(frozen=True, slots=True)
class Finding:
    detector: str
    category: str
    confidence: float
    severity: Severity
    message: str
    spans: tuple[Span, ...] = ()
    properties: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        for start, end in self.spans:
            if start < 0 or end < start:
                raise ValueError("finding spans must satisfy 0 <= start <= end")
