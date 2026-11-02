"""Scanner execution engine running security rules against target adapters."""

import asyncio
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from lume.adapters.base import BaseTargetAdapter
from lume.core.rule_loader.base import BaseRule
from lume.core.verdict.models import (
    ScanReport,
    SeverityLevel,
    Verdict,
    VerdictStatus,
)


class ScanOptions(BaseModel):
    """Configuration options for a scan run."""
    target_name: str = Field(..., description="Target identifier/name")
    rules: List[str] = Field(default_factory=list, description="IDs of rules to execute (empty = all)")
    concurrency: int = Field(default=2, ge=1, le=10, description="Max concurrent rules running")
    timeout_per_rule: float = Field(default=30.0, description="Timeout in seconds per rule")
    stop_on_critical: bool = Field(default=False, description="Abort scan upon first CRITICAL finding")
    proxy: Optional[str] = Field(default=None, description="Upstream proxy URL")
    verify: bool = Field(default=True, description="Verify TLS certificates")
    cert: Optional[str] = Field(default=None, description="Client certificate PEM path")
    delay_ms: int = Field(default=0, ge=0, description="Rate-limiting delay between requests in milliseconds")
    user_agent: Optional[str] = Field(default=None, description="Custom User-Agent header")

    model_config = {"arbitrary_types_allowed": True}


class ScannerEngine:
    """Enterprise scanning engine coordinating rule execution, error isolation, and metrics."""

    def __init__(self, target_adapter: BaseTargetAdapter):
        self.target = target_adapter

    def calculate_risk_score(self, verdicts: List[Verdict]) -> float:
        """Calculate a composite risk score (0-100) based on severity of findings."""
        if not verdicts:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 25.0,
            SeverityLevel.HIGH: 15.0,
            SeverityLevel.MEDIUM: 8.0,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFO: 0.0,
        }

        raw_score = 0.0
        for v in verdicts:
            if v.status == VerdictStatus.VULNERABLE:
                weight = severity_weights.get(v.severity, 5.0)
                raw_score += weight * v.confidence

        return min(round(raw_score, 1), 100.0)

    async def _execute_single_rule(
        self,
        rule: BaseRule,
        timeout: float,
        context: Dict[str, Any],
    ) -> Verdict:
        """Execute one rule with timeout and error boundary."""
        start_t = time.perf_counter()
        try:
            verdict = await asyncio.wait_for(
                rule.evaluate(self.target, context=context),
                timeout=timeout,
            )
            verdict.execution_time_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return verdict
        except asyncio.TimeoutError:
            return rule.create_verdict(
                status=VerdictStatus.INCONCLUSIVE,
                notes=f"Evaluation timed out after {timeout}s",
                execution_time_ms=round((time.perf_counter() - start_t) * 1000, 2),
            )
        except Exception as exc:
            return rule.create_verdict(
                status=VerdictStatus.ERROR,
                notes=f"Execution error: {type(exc).__name__}: {str(exc)}",
                execution_time_ms=round((time.perf_counter() - start_t) * 1000, 2),
            )

    async def run_scan_async(
        self,
        rules: List[BaseRule],
        options: Optional[ScanOptions] = None,
        on_rule_start: Optional[Callable[[BaseRule], None]] = None,
        on_rule_complete: Optional[Callable[[Verdict], None]] = None,
    ) -> ScanReport:
        """Execute security rules asynchronously with controlled concurrency."""
        scan_id = str(uuid.uuid4())[:8]
        concurrency = options.concurrency if options else 2
        timeout = options.timeout_per_rule if options else 30.0
        target_label = options.target_name if options else self.target.config.endpoint

        semaphore = asyncio.Semaphore(concurrency)
        verdicts: List[Verdict] = []
        scan_start = time.perf_counter()

        async def worker(rule: BaseRule) -> Verdict:
            async with semaphore:
                if on_rule_start:
                    on_rule_start(rule)
                res = await self._execute_single_rule(
                    rule=rule,
                    timeout=timeout,
                    context={"scan_id": scan_id, "target": target_label},
                )
                if on_rule_complete:
                    on_rule_complete(res)
                return res

        # Run with asyncio gather
        tasks = [worker(rule) for rule in rules]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        verdicts.extend(results)

        total_duration = round(time.perf_counter() - scan_start, 2)

        vulnerable_count = sum(1 for v in verdicts if v.status == VerdictStatus.VULNERABLE)
        blocked_count = sum(1 for v in verdicts if v.status in (VerdictStatus.BLOCKED, VerdictStatus.SECURE))
        inconclusive_count = sum(1 for v in verdicts if v.status == VerdictStatus.INCONCLUSIVE)
        error_count = sum(1 for v in verdicts if v.status == VerdictStatus.ERROR)
        risk_score = self.calculate_risk_score(verdicts)

        return ScanReport(
            scan_id=scan_id,
            target=target_label,
            duration_seconds=total_duration,
            total_rules=len(rules),
            vulnerable_count=vulnerable_count,
            blocked_count=blocked_count,
            inconclusive_count=inconclusive_count,
            error_count=error_count,
            verdicts=verdicts,
            overall_risk_score=risk_score,
            metadata={
                "adapter": self.target.adapter_type,
                "concurrency": concurrency,
                "proxy": getattr(self.target, "proxy", None),
                "verify": getattr(self.target, "verify", True),
                "cert": getattr(self.target, "cert", None),
                "delay_ms": getattr(self.target, "delay_ms", 0),
                "user_agent": getattr(self.target, "user_agent", None),
            },
        )

    def run_scan(
        self,
        rules: List[BaseRule],
        options: Optional[ScanOptions] = None,
        on_rule_start: Optional[Callable[[BaseRule], None]] = None,
        on_rule_complete: Optional[Callable[[Verdict], None]] = None,
    ) -> ScanReport:
        """Synchronous wrapper for scan execution."""
        return asyncio.run(
            self.run_scan_async(
                rules=rules,
                options=options,
                on_rule_start=on_rule_start,
                on_rule_complete=on_rule_complete,
            )
        )
