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
