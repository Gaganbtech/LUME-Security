"""Dev 6 reporting tests. Run: python -m pytest tests/unit/test_reporting_formats.py"""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from lume.cli.main import app
from lume.core.verdict.models import Evidence, ScanReport, SeverityLevel, Verdict, VerdictStatus
from lume.reporting.html_reporter import HTMLReporter
from lume.reporting.sarif_reporter import SARIFReporter


def sample_report():
    return ScanReport(
        scan_id="dev6-test", target="http://user:secret@localhost:8000/v1/chat?token=secret",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), total_rules=3,
        vulnerable_count=1, blocked_count=1, inconclusive_count=1, overall_risk_score=25.0,
        verdicts=[
            Verdict(rule_id="PI-001", rule_name="Injection", category="prompt_injection",
                    status=VerdictStatus.VULNERABLE, severity=SeverityLevel.CRITICAL, confidence=.9,
                    evidence=Evidence(payload='<script>alert(1)</script> sk-secret123456',
                                      response_snippet='Authorization: Bearer abc123456789', notes='Observed attack'),
                    recommendation='Escape <unsafe> data'),
            Verdict(rule_id="PI-002", rule_name="Block", category="prompt_injection",
                    status=VerdictStatus.BLOCKED, severity=SeverityLevel.HIGH),
            Verdict(rule_id="PI-003", rule_name="Uncertain", category="prompt_injection",
                    status=VerdictStatus.INCONCLUSIVE, severity=SeverityLevel.MEDIUM),
        ],
    )


def test_sarif_structure_and_no_unverified_alerts(tmp_path):
    path = SARIFReporter().generate(sample_report(), tmp_path / 'subdir' / 'audit.sarif')
    data = json.loads(path.read_text())
    assert data['version'] == '2.1.0'
    assert len(data['runs'][0]['tool']['driver']['rules']) == 3
    assert len(data['runs'][0]['results']) == 1
    assert data['runs'][0]['results'][0]['ruleId'] == 'PI-001'
    assert data['runs'][0]['results'][0]['level'] == 'error'
    assert 'secret' not in json.dumps(data).lower()
    assert 'localhost:8000/v1/chat' in json.dumps(data)


def test_html_offline_escaping_filter_and_copy(tmp_path):
    path = HTMLReporter().generate(sample_report(), tmp_path / 'audit.html')
    doc = path.read_text()
    assert '&lt;script&gt;' in doc and '<script>alert(1)</script>' not in doc
    assert 'sk-secret123456' not in doc
    assert 'Bearer abc123456789' not in doc
    assert 'user:secret' not in doc and '?token=' not in doc
    assert 'data-filter="INCONCLUSIVE"' in doc and 'button.copy' in doc
    assert 'https://' not in doc and 'http://' in doc  # local target only
    assert '{{ROWS}}' not in doc


def test_default_extensions(tmp_path):
    r = sample_report()
    assert SARIFReporter(tmp_path).generate(r).suffix == '.sarif'
    assert HTMLReporter(tmp_path).generate(r).suffix == '.html'


def test_cli_reporting_options(tmp_path):
    runner = CliRunner()
    report = sample_report()

    with patch("lume.cli.main.ScannerEngine") as mock_engine_cls, \
         patch("lume.cli.main.RuleRegistry.get_all") as mock_get_rules:
        mock_rule = MagicMock()
        mock_rule.category = "prompt_injection"
        mock_rule.rule_id = "PI-001"
        mock_get_rules.return_value = [mock_rule]

        mock_engine = MagicMock()
        mock_engine.run_scan.return_value = report
        mock_engine_cls.return_value = mock_engine

        # Test SARIF output flag
        sarif_file = tmp_path / "cli_scan.sarif"
        result_sarif = runner.invoke(app, [
            "scan", "-t", "http://localhost:8000/v1/chat", "--authorized",
            "--output", "sarif", "--report-file", str(sarif_file)
        ])
        assert result_sarif.exit_code == 0
        assert sarif_file.exists()
        sarif_json = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert sarif_json["version"] == "2.1.0"
        assert "PI-001" in sarif_file.read_text(encoding="utf-8")

        # Test HTML output flag
        html_file = tmp_path / "cli_scan.html"
        result_html = runner.invoke(app, [
            "scan", "-t", "http://localhost:8000/v1/chat", "--authorized",
            "--output", "html", "--report-file", str(html_file)
        ])
        assert result_html.exit_code == 0
        assert html_file.exists()
        assert "<!doctype html>" in html_file.read_text(encoding="utf-8")

        # Test invalid output format flag
        result_invalid = runner.invoke(app, [
            "scan", "-t", "http://localhost:8000/v1/chat", "--authorized",
            "--output", "invalid_format"
        ])
        assert result_invalid.exit_code == 2
        assert "Invalid --output" in result_invalid.output
