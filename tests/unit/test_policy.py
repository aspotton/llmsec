from llmsec import Finding, Severity, Stage, Trust
from llmsec.core import DecisionAction, SecurityContext
from llmsec.policy import DefaultPolicy


def test_high_confidence_high_severity_blocks() -> None:
    decision = DefaultPolicy().decide(
        content="x",
        context=SecurityContext(Stage.USER_INPUT, Trust.UNKNOWN),
        findings=(
            Finding(
                detector="test",
                category="attack",
                confidence=0.95,
                severity=Severity.HIGH,
                message="attack",
            ),
        ),
        metrics={},
    )
    assert decision.action is DecisionAction.BLOCK


def test_medium_severity_does_not_block_by_default() -> None:
    decision = DefaultPolicy().decide(
        content="x",
        context=SecurityContext(Stage.USER_INPUT, Trust.UNKNOWN),
        findings=(
            Finding(
                detector="test",
                category="warning",
                confidence=0.99,
                severity=Severity.MEDIUM,
                message="warning",
            ),
        ),
        metrics={},
    )
    assert decision.action is DecisionAction.ALLOW
