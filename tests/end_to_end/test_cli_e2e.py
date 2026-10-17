"""End-to-End CLI tests validating the complete scan-to-report workflow."""

import json
from pathlib import Path

from typer.testing import CliRunner

from lume.cli.main import app

runner = CliRunner()


def test_cli_scan_e2e_vulnerable_target(vulnerable_server_url: str, tmp_path: Path):
    """Run full CLI scan against vulnerable target and verify report generation."""
    report_file = tmp_path / "e2e_report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "prompt-injection",
            "--target",
            vulnerable_server_url,
            "--report-file",
            str(report_file),
            "--concurrency",
            "2",
        ],
    )

    assert result.exit_code == 0
    assert "Initiating Security Scan" in result.output
    assert "Rule Evaluation Verdicts" in result.output
    assert "VULNERABILITY FINDINGS & REMEDIATION STEPS" in result.output

    # Verify JSON report on disk
    assert report_file.exists()
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["target"] == vulnerable_server_url
    assert data["total_rules"] == 6
    assert data["vulnerable_count"] > 0
    assert "overall_risk_score" in data


def test_cli_scan_e2e_protected_target(protected_server_url: str, tmp_path: Path):
    """Run full CLI scan against protected target and verify clean summary."""
    report_file = tmp_path / "e2e_protected_report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            protected_server_url,
            "--report-file",
            str(report_file),
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerable prompt injection behaviors confirmed" in result.output

    # Verify JSON report on disk
    assert report_file.exists()
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["vulnerable_count"] == 0
    assert data["blocked_count"] > 0
    assert data["overall_risk_score"] == 0.0
