from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from inspect import isawaitable
from typing import Protocol

from llmsec.content import ContentViews
from llmsec.core import DetectorCost, Finding, SecurityContext, Stage


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    name: str
    stages: frozenset[Stage]
    cost: DetectorCost = DetectorCost.LINEAR
    timeout_ms: int = 10


class Detector(Protocol):
    spec: DetectorSpec

    async def inspect(
        self,
        context: SecurityContext,
        views: ContentViews,
    ) -> list[Finding]: ...


DetectorFunction = Callable[
    [SecurityContext, ContentViews],
    list[Finding] | Awaitable[list[Finding]],
]


@dataclass(slots=True)
class FunctionDetector:
    spec: DetectorSpec
    function: DetectorFunction

    async def inspect(
        self,
        context: SecurityContext,
        views: ContentViews,
    ) -> list[Finding]:
        result = self.function(context, views)
        if isawaitable(result):
            return await result
        return result


def detector(
    *,
    name: str,
    stages: frozenset[Stage] | None = None,
    cost: DetectorCost = DetectorCost.LINEAR,
    timeout_ms: int = 10,
) -> Callable[[DetectorFunction], FunctionDetector]:
    selected_stages = frozenset(Stage) if stages is None else stages

    def wrap(function: DetectorFunction) -> FunctionDetector:
        return FunctionDetector(
            spec=DetectorSpec(
                name=name,
                stages=selected_stages,
                cost=cost,
                timeout_ms=timeout_ms,
            ),
            function=function,
        )

    return wrap
