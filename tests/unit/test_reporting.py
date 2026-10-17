"""Unit tests for EvidenceCollector, JSONReporter, and ConsoleReporter."""

import json
from pathlib import Path

from rich.console import Console

from lume.core.verdict.models import (
    Evidence,
    ScanReport,
    SeverityLevel,
    Verdict,
    VerdictStatus,
)
from lume.evidence.collector import EvidenceCollector
from lume.reporting.console_reporter import ConsoleReporter
from lume.reporting.json_reporter import JSONReporter
from lume.utils.redaction import redact_sensitive_text


def test_redaction_utility():
    text = "API Key: sk-proj-1234567890abcdef1234567890abcdef and Bearer 1234567890abcdef12345678"
    redacted = redact_sensitive_text(text)
    assert "sk-proj" not in redacted
    assert "[REDACTED" in redacted


def test_evidence_collector():
    collector = EvidenceCollector()
    collector.record(
        rule_id="PI-001",
        test_id="T1",
        raw_payload="test payload with sk-1234567890abcdef1234567890abcdef",
        raw_response="test response",
        matched_patterns=["pattern1"],
        status_code=200,
        is_vulnerable=True,
    )
    entries = collector.get_entries_for_rule("PI-001")
    assert len(entries) == 1
    assert entries[0].is_vulnerable is True
    assert "[REDACTED" in entries[0].payload_preview


def test_json_and_console_reporting(tmp_path: Path):
    report = ScanReport(
        scan_id="test1234",
        target="http://localhost:8000",
        duration_seconds=1.5,
        total_rules=1,
        vulnerable_count=1,
        blocked_count=0,
        verdicts=[
            Verdict(
                rule_id="PI-001",
                rule_name="Direct Override",
                category="prompt_injection",
                severity=SeverityLevel.CRITICAL,
                status=VerdictStatus.VULNERABLE,
                confidence=1.0,
                recommendation="Lock system instruction boundaries.",
                evidence=Evidence(
                    payload="Override prompt",
                    response_snippet="Canary confirmed",
                    matched_patterns=["CANARY"],
                ),
            )
        ],
        overall_risk_score=25.0,
    )

    # Test JSON reporter
    reporter = JSONReporter(output_dir=tmp_path)
    output_file = reporter.generate(report)
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["scan_id"] == "test1234"
    assert data["vulnerable_count"] == 1
    assert len(data["verdicts"]) == 1

    # Test Console reporter rendering without exceptions
    console = Console(record=True)
    console_reporter = ConsoleReporter(console)
    console_reporter.render_report(report)
    output = console.export_text()
    assert "PI-001" in output
    assert "VULNERABLE" in output
    assert "Remediation Guidance" in output
