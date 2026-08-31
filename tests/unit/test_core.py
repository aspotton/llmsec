from itertools import pairwise

import pytest

from llmsec import DecisionAction, Finding, Severity, Stage, Trust
from llmsec.core import Decision, SecurityContext, severity_rank


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


def test_severity_rank_strictly_increasing_in_declaration_order() -> None:
    # list(Severity) is declaration order (LOW, MEDIUM, HIGH, CRITICAL);
    # sorted(Severity) would order by the value strings and be non-monotonic.
    ranks = [severity_rank(severity) for severity in list(Severity)]
    assert all(later > earlier for earlier, later in pairwise(ranks))


def test_severity_rank_raises_key_error_for_unknown_value() -> None:
    with pytest.raises(KeyError):
        severity_rank("bogus")  # type: ignore[arg-type]
