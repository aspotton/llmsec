from enum import StrEnum


class Stage(StrEnum):
    USER_INPUT = "user.input"
    RETRIEVAL_DOCUMENT = "retrieval.document"
    TOOL_RESULT = "tool.result"
    MODEL_OUTPUT = "model.output"


class Profile(StrEnum):
    CHAT = "chat"
    RAG = "rag"
    AGENT = "agent"


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def severity_rank(severity: Severity) -> int:
    """Return the ordinal rank of a severity (LOW=1 ... CRITICAL=4).

    The mapping is an explicit table: a future ``Severity`` member missing
    here raises ``KeyError`` on first use, kept deliberately as an
    exhaustiveness tripwire rather than a silent default.
    """
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]


class DecisionAction(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    CONFIRM = "confirm"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"


class DetectorCost(StrEnum):
    CONSTANT = "constant"
    LINEAR = "linear"
    MODEL = "model"
    DEEP = "deep"
