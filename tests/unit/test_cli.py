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
