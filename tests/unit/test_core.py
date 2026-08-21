from llmsec import DecisionAction, Finding, Severity, Stage, Trust
from llmsec.core import Decision, SecurityContext


def test_security_context_uses_typed_values() -> None:
    context = SecurityContext(stage=Stage.RETRIEVAL_DOCUMENT, trust=Trust.UNTRUSTED)
    assert context.stage is Stage.RETRIEVAL_DOCUMENT
    assert context.trust is Trust.UNTRUSTED


def test_finding_rejects_invalid_confidence() -> None:
    try:
        Finding(
            detector="test",
            category="test",
            confidence=1.1,
            severity=Severity.LOW,
            message="bad confidence",
        )
    except ValueError as exc:
        assert "confidence" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_decision_helpers() -> None:
    allowed = Decision(action=DecisionAction.ALLOW, content="ok")
    blocked = Decision(action=DecisionAction.BLOCK, content="no")
    assert allowed.allowed
    assert not allowed.blocked
    assert blocked.blocked
    assert not blocked.allowed
