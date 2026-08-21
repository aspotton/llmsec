import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass

from llmsec.content import ContentViews
from llmsec.core import Finding, SecurityContext
from llmsec.detectors.base import Detector


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    findings: tuple[Finding, ...]
    detector_ms: dict[str, float]


async def _run_detector(
    detector: Detector,
    context: SecurityContext,
    views: ContentViews,
) -> tuple[list[Finding], float]:
    started = time.perf_counter()
    timeout = detector.spec.timeout_ms / 1000
    findings = await asyncio.wait_for(detector.inspect(context, views), timeout=timeout)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return findings, elapsed_ms


async def execute_detectors(
    detectors: Iterable[Detector],
    context: SecurityContext,
    views: ContentViews,
) -> ExecutionResult:
    selected = [detector for detector in detectors if context.stage in detector.spec.stages]
    if not selected:
        return ExecutionResult(findings=(), detector_ms={})

    outcomes = await asyncio.gather(
        *(_run_detector(detector, context, views) for detector in selected)
    )
    findings: list[Finding] = []
    metrics: dict[str, float] = {}
    for detector, (detector_findings, elapsed_ms) in zip(selected, outcomes, strict=True):
        findings.extend(detector_findings)
        metrics[detector.spec.name] = elapsed_ms
    return ExecutionResult(findings=tuple(findings), detector_ms=metrics)
