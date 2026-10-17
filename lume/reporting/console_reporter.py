"""Terminal console reporting using Rich tables and remediation guides."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lume.core.verdict.models import ScanReport, SeverityLevel, VerdictStatus


class ConsoleReporter:
    """Renders formatted scan summaries, finding tables, and remediation guidance."""

    def __init__(self, console: Console):
        self.console = console

    def render_report(self, report: ScanReport) -> None:
        """Render the complete scan report to the terminal."""
        # 1. Summary Metrics Panel
        risk_color = "green"
        if report.overall_risk_score >= 50.0:
            risk_color = "bold red"
        elif report.overall_risk_score >= 20.0:
            risk_color = "bold yellow"

        summary_text = Text()
        summary_text.append(f"Scan ID: {report.scan_id}  |  Target: {report.target}\n", style="bold cyan")
        summary_text.append(f"Duration: {report.duration_seconds}s  |  Total Rules: {report.total_rules}\n", style="dim")
        summary_text.append(f"VULNERABLE: {report.vulnerable_count}  ", style="bold red")
        summary_text.append(f"BLOCKED: {report.blocked_count}  ", style="bold green")
        summary_text.append(f"INCONCLUSIVE: {report.inconclusive_count}  ", style="bold yellow")
        summary_text.append(f"ERRORS: {report.error_count}\n", style="bold magenta")
        summary_text.append("Overall Risk Score: ", style="bold white")
        summary_text.append(f"{report.overall_risk_score} / 100", style=risk_color)

        self.console.print(
            Panel(
                summary_text,
                title="[bold bright_blue]LUME Security Assessment Summary[/bold bright_blue]",
                border_style="bright_blue",
            )
        )

        # 2. Verdicts Table
        table = Table(title="Rule Evaluation Verdicts", border_style="cyan")
        table.add_column("Rule ID", style="bold yellow")
        table.add_column("Rule Name", style="bold white")
        table.add_column("Severity", style="magenta")
        table.add_column("Verdict", style="bold")
        table.add_column("Confidence", style="dim")
        table.add_column("Latency (ms)", style="dim")

        for v in report.verdicts:
            verdict_style = {
                VerdictStatus.VULNERABLE: "bold red",
                VerdictStatus.BLOCKED: "bold green",
                VerdictStatus.INCONCLUSIVE: "bold yellow",
                VerdictStatus.ERROR: "bold magenta",
            }.get(v.status, "white")

            sev_style = {
                SeverityLevel.CRITICAL: "bold red",
                SeverityLevel.HIGH: "red",
                SeverityLevel.MEDIUM: "yellow",
                SeverityLevel.LOW: "blue",
                SeverityLevel.INFO: "dim white",
            }.get(v.severity, "white")

            table.add_row(
                v.rule_id,
                v.rule_name,
                f"[{sev_style}]{v.severity.value}[/{sev_style}]",
                f"[{verdict_style}]{v.status.value}[/{verdict_style}]",
                f"{int(v.confidence * 100)}%",
                f"{v.execution_time_ms:.1f}",
            )

        self.console.print(table)

        # 3. Remediation Guide for Vulnerable Findings
        vulnerabilities = [v for v in report.verdicts if v.status == VerdictStatus.VULNERABLE]
        if vulnerabilities:
            self.console.print("\n[bold red]⚠️ VULNERABILITY FINDINGS & REMEDIATION STEPS[/bold red]")
            for idx, v in enumerate(vulnerabilities, start=1):
                evidence_text = "None recorded"
                if v.evidence:
                    evidence_text = f"Payload: {v.evidence.payload}\nObserved Output: {v.evidence.response_snippet}"

                remediation_content = Text()
                remediation_content.append(f"Severity: {v.severity.value}\n", style="bold red")
                remediation_content.append("Evidence:\n", style="bold white")
                remediation_content.append(f"{evidence_text}\n\n", style="dim")
                remediation_content.append("Remediation Guidance:\n", style="bold green")
                remediation_content.append(v.recommendation or "Review LLM system prompt boundaries and input sanitization.", style="white")

                self.console.print(
                    Panel(
                        remediation_content,
                        title=f"[bold yellow]Finding #{idx}: [{v.rule_id}] {v.rule_name}[/bold yellow]",
                        border_style="red",
                    )
                )
        else:
            self.console.print("\n[bold green]✓ No vulnerable prompt injection behaviors confirmed in this scan.[/bold green]")
