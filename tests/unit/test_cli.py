"""Unit tests for LUME CLI commands."""

from typer.testing import CliRunner

from lume import __version__
from lume.cli.main import app
from lume.core.rule_loader.base import RuleRegistry

runner = CliRunner()


def test_cli_help():
    """Verify `lume --help` exits with code 0 and lists subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "LUME: Enterprise AI Security CLI Toolkit" in result.output
    assert "scan" in result.output
    assert "version" in result.output
    assert "list-rules" in result.output
    assert "info" in result.output


def test_cli_version_flag():
    """Verify `lume --version` prints version string and exits cleanly."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"v{__version__}" in result.output


def test_cli_version_command():
    """Verify `lume version` prints banner and system info."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "LUME" in result.output
    assert f"v{__version__}" in result.output
    assert "Python Runtime" in result.output


def test_cli_info_command():
    """Verify `lume info` prints environment diagnostics."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "System Diagnostics" in result.output
    assert "OWASP LLM Target Scope" in result.output


def test_cli_list_rules_empty():
    """Verify `lume list-rules` handles empty registry gracefully."""
    RuleRegistry.clear()
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0
    assert "No rules currently loaded in registry" in result.output


def test_cli_list_rules_populated():
    """Verify `lume list-rules` displays table when rules exist."""
    RuleRegistry.clear()
    from lume.adapters.base import BaseTargetAdapter
    from lume.core.rule_loader.base import BaseRule, RuleMetadata
    from lume.core.verdict.models import SeverityLevel, Verdict, VerdictStatus

    class SampleRule(BaseRule):
        async def evaluate(self, target: BaseTargetAdapter, context=None) -> Verdict:
            return self.create_verdict(status=VerdictStatus.SECURE)

    meta = RuleMetadata(
        rule_id="PI-001",
        name="Direct Override Rule",
        description="Test direct prompt injection override",
        category="prompt_injection",
        severity=SeverityLevel.HIGH,
    )
    RuleRegistry.register(SampleRule(meta))

    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0
    assert "PI-001" in result.output
    assert "Direct Override Rule" in result.output
    RuleRegistry.clear()


def test_cli_scan_help_pentest_options():
    """Verify `lume scan --help` includes all pentester networking options."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--proxy" in result.output
    assert "--insecure" in result.output
    assert "-k" in result.output
    assert "--delay-ms" in result.output
    assert "--user-agent" in result.output
    assert "--cert" in result.output


def test_cli_scan_with_pentest_flags(monkeypatch):
    """Verify scan command initializes adapter and scanner options with pentest arguments."""
    from unittest.mock import MagicMock, patch

    from lume.core.verdict.models import ScanReport

    captured_adapter = []

    mock_report = ScanReport(
        scan_id="test-scan",
        target="http://localhost:8000/v1/chat",
        duration_seconds=0.5,
        total_rules=1,
        verdicts=[],
    )

    with patch("lume.cli.main.ScannerEngine") as mock_engine_cls, \
         patch("lume.cli.main.RuleRegistry.get_all") as mock_get_rules:
        mock_rule = MagicMock()
        mock_rule.category = "prompt_injection"
        mock_rule.rule_id = "PI-001"
        mock_get_rules.return_value = [mock_rule]

        mock_engine = MagicMock()
        mock_engine.run_scan.return_value = mock_report
        mock_engine_cls.side_effect = lambda adapter: captured_adapter.append(adapter) or mock_engine

        result = runner.invoke(
            app,
            [
                "scan",
                "-t",
                "http://localhost:8000/v1/chat",
                "--authorized",
                "--proxy",
                "http://127.0.0.1:8080",
                "-k",
                "--delay-ms",
                "150",
                "--user-agent",
                "BurpSuite-LUME/1.0",
            ],
        )

        assert result.exit_code == 0
        assert len(captured_adapter) == 1
        adapter = captured_adapter[0]
        assert adapter.proxy == "http://127.0.0.1:8080"
        assert adapter.verify is False
        assert adapter.delay_ms == 150
        assert adapter.user_agent == "BurpSuite-LUME/1.0"
        assert adapter.default_headers["User-Agent"] == "BurpSuite-LUME/1.0"

        # Check call arguments to run_scan
        mock_engine.run_scan.assert_called_once()
        scan_opts = mock_engine.run_scan.call_args.kwargs["options"]
        assert scan_opts.proxy == "http://127.0.0.1:8080"
        assert scan_opts.verify is False
        assert scan_opts.delay_ms == 150
        assert scan_opts.user_agent == "BurpSuite-LUME/1.0"


def test_cli_scan_with_long_insecure_flag():
    """Verify --insecure flag disables TLS verification."""
    from unittest.mock import MagicMock, patch

    from lume.core.verdict.models import ScanReport

    captured_adapter = []
    mock_report = ScanReport(
        scan_id="test-scan",
        target="http://localhost:8000/v1/chat",
        duration_seconds=0.5,
        total_rules=1,
        verdicts=[],
    )

    with patch("lume.cli.main.ScannerEngine") as mock_engine_cls, \
         patch("lume.cli.main.RuleRegistry.get_all") as mock_get_rules:
        mock_rule = MagicMock()
        mock_rule.category = "prompt_injection"
        mock_rule.rule_id = "PI-001"
        mock_get_rules.return_value = [mock_rule]

        mock_engine = MagicMock()
        mock_engine.run_scan.return_value = mock_report
        mock_engine_cls.side_effect = lambda adapter: captured_adapter.append(adapter) or mock_engine

        result = runner.invoke(
            app,
            [
                "scan",
                "-t",
                "http://localhost:8000/v1/chat",
                "--authorized",
                "--insecure",
            ],
        )

        assert result.exit_code == 0
        assert len(captured_adapter) == 1
        assert captured_adapter[0].verify is False


def test_cli_scan_with_cert_flag():
    """Verify --cert flag propagates client certificate path to adapter."""
    from unittest.mock import MagicMock, patch

    from lume.core.verdict.models import ScanReport

    captured_adapter = []
    mock_report = ScanReport(
        scan_id="test-scan",
        target="http://localhost:8000/v1/chat",
        duration_seconds=0.5,
        total_rules=1,
        verdicts=[],
    )

    with patch("lume.cli.main.ScannerEngine") as mock_engine_cls, \
         patch("lume.cli.main.RuleRegistry.get_all") as mock_get_rules:
        mock_rule = MagicMock()
        mock_rule.category = "prompt_injection"
        mock_rule.rule_id = "PI-001"
        mock_get_rules.return_value = [mock_rule]

        mock_engine = MagicMock()
        mock_engine.run_scan.return_value = mock_report
        mock_engine_cls.side_effect = lambda adapter: captured_adapter.append(adapter) or mock_engine

        result = runner.invoke(
            app,
            [
                "scan",
                "-t",
                "http://localhost:8000/v1/chat",
                "--authorized",
                "--cert",
                "/etc/lume/client.pem",
                "-k",
            ],
        )

        assert result.exit_code == 0
        assert len(captured_adapter) == 1
        adapter = captured_adapter[0]
        assert adapter.cert == "/etc/lume/client.pem"
        assert adapter.verify is False

        scan_opts = mock_engine.run_scan.call_args.kwargs["options"]
        assert scan_opts.cert == "/etc/lume/client.pem"
