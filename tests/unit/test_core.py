"""Unit tests for LUME core contracts, rule loader, and scanner engine."""

from typing import Any, Dict, Optional

import pytest

from lume.adapters.base import BaseTargetAdapter, TargetConfig, TargetResponse
from lume.core.rule_loader.base import BaseRule, RuleMetadata, RuleRegistry
from lume.core.scanner.runner import ScannerEngine
from lume.core.verdict.models import SeverityLevel, Verdict, VerdictStatus


class MockTargetAdapter(BaseTargetAdapter):
    """Mock target adapter for testing core engine."""

    @property
    def adapter_type(self) -> str:
        return "mock"

    def send_prompt(self, prompt: str, **kwargs: Any) -> TargetResponse:
        return TargetResponse(raw_text="Safe test response", status_code=200, latency_ms=12.5)

    async def send_prompt_async(self, prompt: str, **kwargs: Any) -> TargetResponse:
        return self.send_prompt(prompt, **kwargs)

    def health_check(self) -> bool:
        return True


class DummyRule(BaseRule):
    """Dummy rule implementation for testing."""

    async def evaluate(
        self,
        target: BaseTargetAdapter,
        context: Optional[Dict[str, Any]] = None,
    ) -> Verdict:
        resp = await target.send_prompt_async("test prompt")
        if "vulnerable" in resp.raw_text.lower():
            return self.create_verdict(status=VerdictStatus.VULNERABLE)
        return self.create_verdict(status=VerdictStatus.SECURE)


def test_rule_registry():
    """Verify RuleRegistry properly registers and retrieves rules."""
    RuleRegistry.clear()
    metadata = RuleMetadata(
        rule_id="PI-TEST-001",
        name="Test Injection Rule",
        description="Verifies rule registry contract",
        category="prompt_injection",
        severity=SeverityLevel.HIGH,
    )
    rule = DummyRule(metadata)
    RuleRegistry.register(rule)

    assert RuleRegistry.get("PI-TEST-001") == rule
    assert len(RuleRegistry.get_all()) == 1
    assert len(RuleRegistry.filter_by_category("prompt_injection")) == 1
    assert len(RuleRegistry.filter_by_category("non_existent")) == 0

    RuleRegistry.clear()
    assert len(RuleRegistry.get_all()) == 0


def test_scanner_risk_score_calculation():
    """Verify composite risk score computation."""
    target = MockTargetAdapter(TargetConfig(endpoint="http://mock-target.internal"))
    engine = ScannerEngine(target)

    # Empty verdicts -> 0 risk
    assert engine.calculate_risk_score([]) == 0.0

    verdicts = [
        Verdict(
            rule_id="PI-001",
            rule_name="Direct Override",
            category="prompt_injection",
            severity=SeverityLevel.CRITICAL,
            status=VerdictStatus.VULNERABLE,
            confidence=1.0,
        ),
        Verdict(
            rule_id="PI-002",
            rule_name="Goal Hijacking",
            category="prompt_injection",
            severity=SeverityLevel.HIGH,
            status=VerdictStatus.VULNERABLE,
            confidence=1.0,
        ),
        Verdict(
            rule_id="PI-003",
            rule_name="Delimiter Escape",
            category="prompt_injection",
            severity=SeverityLevel.MEDIUM,
            status=VerdictStatus.SECURE,
            confidence=1.0,
        ),
    ]

    # CRITICAL (25) + HIGH (15) = 40.0
    score = engine.calculate_risk_score(verdicts)
    assert score == 40.0


@pytest.mark.asyncio
async def test_scanner_engine_async_execution():
    """Verify scanner engine executes rules and produces a ScanReport."""
    target = MockTargetAdapter(TargetConfig(endpoint="http://mock-target.internal"))
    engine = ScannerEngine(target)

    meta = RuleMetadata(
        rule_id="PI-001",
        name="Mock Rule",
        description="Mock evaluation",
        category="prompt_injection",
        severity=SeverityLevel.HIGH,
    )
    rule = DummyRule(meta)

    report = await engine.run_scan_async(rules=[rule])

    assert report.total_rules == 1
    assert report.secure_count == 1
    assert report.vulnerable_count == 0
    assert report.error_count == 0
    assert len(report.verdicts) == 1
    assert report.verdicts[0].status == VerdictStatus.SECURE
