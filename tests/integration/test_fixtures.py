"""Integration tests scanning against synthetic vulnerable and protected AI HTTP fixtures."""

import pytest

from lume.adapters.base import TargetConfig
from lume.adapters.http.client import HTTPTargetAdapter
from lume.core.rule_loader.base import RuleRegistry
from lume.core.scanner.runner import ScannerEngine, ScanOptions
from lume.core.verdict.models import VerdictStatus


@pytest.mark.asyncio
async def test_scan_vulnerable_ai_fixture(vulnerable_server_url: str):
    """Scan against vulnerable HTTP fixture and verify vulnerabilities are detected and reported."""
    config = TargetConfig(endpoint=vulnerable_server_url, adapter_type="http", timeout=5.0)
    adapter = HTTPTargetAdapter(config)
    engine = ScannerEngine(adapter)

    rules = RuleRegistry.get_all()
    assert len(rules) >= 6

    options = ScanOptions(
        target_name=vulnerable_server_url,
        concurrency=3,
        timeout_per_rule=5.0,
    )

    report = await engine.run_scan_async(rules=rules, options=options)

    # Vulnerable target should trigger vulnerabilities
    assert report.total_rules == len(rules)
    assert report.vulnerable_count > 0
    assert report.overall_risk_score > 0.0

    # Ensure findings have evidence and remediation guidance attached
    vulnerable_findings = [v for v in report.verdicts if v.status == VerdictStatus.VULNERABLE]
    for finding in vulnerable_findings:
        assert finding.evidence is not None
        assert finding.recommendation is not None
        assert finding.execution_time_ms > 0.0


@pytest.mark.asyncio
async def test_scan_protected_ai_fixture(protected_server_url: str):
    """Scan against protected HTTP fixture and verify attacks are blocked."""
    config = TargetConfig(endpoint=protected_server_url, adapter_type="http", timeout=5.0)
    adapter = HTTPTargetAdapter(config)
    engine = ScannerEngine(adapter)

    rules = RuleRegistry.get_all()
    options = ScanOptions(
        target_name=protected_server_url,
        concurrency=3,
        timeout_per_rule=5.0,
    )

    report = await engine.run_scan_async(rules=rules, options=options)

    # Protected target should block attacks
    assert report.total_rules == len(rules)
    assert report.vulnerable_count == 0
    assert report.blocked_count > 0
    assert report.overall_risk_score == 0.0
