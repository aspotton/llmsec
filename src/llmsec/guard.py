import asyncio
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from llmsec.actions.enums import AuthorizationAction
from llmsec.actions.monitor import ReferenceMonitor
from llmsec.actions.types import (
    Approval,
    AuthorizationDecision,
    ToolCall,
    proposal_sha256,
)
from llmsec.content import build_content_views
from llmsec.core import Decision, Finding, Profile, SecurityContext, Stage, Trust
from llmsec.detectors import (
    ContextAnomalyDetector,
    Detector,
    EncodingDetector,
    HeuristicInjectionDetector,
    SecretDetector,
    UnicodeDetector,
)
from llmsec.execution import execute_detectors
from llmsec.policy import DefaultPolicy, Policy

PROFILE_POLICIES: Final[Mapping[Profile, DefaultPolicy]] = {
    Profile.CHAT: DefaultPolicy(),
    Profile.RAG: DefaultPolicy(confirm_threshold=0.80, block_threshold=0.88),
    Profile.AGENT: DefaultPolicy(confirm_threshold=0.85, block_threshold=0.85),
}


@dataclass(slots=True)
class Guard:
    detectors: list[Detector]
    policy: Policy
    diagnostics: bool = False
    # Appended last with a default so legacy positional construction
    # ``Guard(detectors, policy, diagnostics)`` keeps working; keyword-only in
    # practice. Deny-by-default: None means authorize_tool_call never allows.
    monitor: ReferenceMonitor | None = None

    @classmethod
    def default(cls, *, policy: DefaultPolicy | None = None, diagnostics: bool = False) -> "Guard":
        return cls(
            detectors=[
                UnicodeDetector(),
                EncodingDetector(),
                SecretDetector(),
                ContextAnomalyDetector(),
                HeuristicInjectionDetector(),
            ],
            policy=policy or DefaultPolicy(),
            diagnostics=diagnostics,
        )

    @classmethod
    def from_profile(cls, profile: Profile, *, diagnostics: bool = False) -> "Guard":
        return cls.default(policy=PROFILE_POLICIES[profile], diagnostics=diagnostics)

    def add_detector(self, detector: Detector) -> None:
        self.detectors.append(detector)

    def authorize_tool_call(
        self,
        call: ToolCall,
        approval: Approval | None = None,
        findings: tuple[Finding, ...] = (),
    ) -> AuthorizationDecision:
        """Commit gate for a proposed tool call; deny-by-default without a monitor.

        ``findings`` is a host-supplied, tightening-only input, never computed
        here. With no monitor configured this never raises and never allows.
        """
        if self.monitor is None:
            return AuthorizationDecision(
                action=AuthorizationAction.DENY,
                proposal_sha256=proposal_sha256(call),
                reason="no_monitor",
                findings=findings,
            )
        return self.monitor.authorize(call, approval=approval, findings=findings)

    async def ainspect(
        self,
        content: str,
        *,
        stage: Stage = Stage.USER_INPUT,
        trust: Trust = Trust.UNKNOWN,
        context: SecurityContext | None = None,
    ) -> Decision:
        effective_context = context or SecurityContext(stage=stage, trust=trust)
        started = time.perf_counter()

        view_started = time.perf_counter()
        views = build_content_views(content)
        views_ms = (time.perf_counter() - view_started) * 1000

        execution = await execute_detectors(self.detectors, effective_context, views)
        total_ms = (time.perf_counter() - started) * 1000

        metrics: dict[str, float] = {}
        if self.diagnostics:
            metrics = {
                "total_ms": total_ms,
                "content_views_ms": views_ms,
                **{f"detector.{name}_ms": value for name, value in execution.detector_ms.items()},
            }

        return self.policy.decide(
            content=content,
            context=effective_context,
            findings=execution.findings,
            metrics=metrics,
        )

    def inspect(
        self,
        content: str,
        *,
        stage: Stage = Stage.USER_INPUT,
        trust: Trust = Trust.UNKNOWN,
        context: SecurityContext | None = None,
    ) -> Decision:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.ainspect(content, stage=stage, trust=trust, context=context))
        raise RuntimeError(
            "Guard.inspect() cannot run inside an active event loop; use await Guard.ainspect()."
        )

    async def ainspect_many(
        self,
        contents: Iterable[str],
        *,
        stage: Stage = Stage.USER_INPUT,
        trust: Trust = Trust.UNKNOWN,
    ) -> list[Decision]:
        return list(
            await asyncio.gather(
                *(self.ainspect(content, stage=stage, trust=trust) for content in contents)
            )
        )

    def inspect_user_input(self, content: str) -> Decision:
        return self.inspect(content, stage=Stage.USER_INPUT, trust=Trust.UNKNOWN)

    async def ainspect_user_input(self, content: str) -> Decision:
        return await self.ainspect(content, stage=Stage.USER_INPUT, trust=Trust.UNKNOWN)

    def inspect_retrieval(self, content: str) -> Decision:
        return self.inspect(content, stage=Stage.RETRIEVAL_DOCUMENT, trust=Trust.UNTRUSTED)

    async def ainspect_retrieval(self, content: str) -> Decision:
        return await self.ainspect(
            content,
            stage=Stage.RETRIEVAL_DOCUMENT,
            trust=Trust.UNTRUSTED,
        )

    def inspect_tool_result(self, content: str) -> Decision:
        return self.inspect(content, stage=Stage.TOOL_RESULT, trust=Trust.UNTRUSTED)

    async def ainspect_tool_result(self, content: str) -> Decision:
        return await self.ainspect(content, stage=Stage.TOOL_RESULT, trust=Trust.UNTRUSTED)

    def inspect_model_output(self, content: str) -> Decision:
        return self.inspect(content, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)

    async def ainspect_model_output(self, content: str) -> Decision:
        return await self.ainspect(content, stage=Stage.MODEL_OUTPUT, trust=Trust.UNKNOWN)
