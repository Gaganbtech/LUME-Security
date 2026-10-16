"""Main CLI entry point for LUME using Typer and Rich."""

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lume import __app_name__, __version__
from lume.cli.display.banner import detect_environment, print_banner
from lume.core.rule_loader.base import RuleRegistry
from lume.core.verdict.models import SeverityLevel

app = typer.Typer(
    name=__app_name__,
    help="LUME: Enterprise AI Security CLI Toolkit for LLM Vulnerability Assessment & Prompt Injection Scanning.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool):
    """Print version information and exit."""
    if value:
        console.print(f"[bold cyan]LUME-Security[/bold cyan] version [bold green]v{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the LUME version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """LUME Security Toolkit - Assessment Engine for AI & LLM Systems."""
    pass


@app.command("version")
def show_version(
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Show extended environment information."),
):
    """Display LUME toolkit version and execution environment details."""
    print_banner(version=__version__)
    table = Table(title="LUME System Information", border_style="bright_blue")
    table.add_column("Component", style="bold cyan")
    table.add_column("Details", style="white")

    table.add_row("Toolkit Version", f"v{__version__}")
    table.add_row("App Name", __app_name__)
    table.add_row("Python Runtime", sys.version.split()[0])
    table.add_row("Target Platform", detect_environment())

    if verbose:
        table.add_row("Executable Path", sys.executable)
        table.add_row("Architecture", sys.platform)

    console.print(table)


@app.command("list-rules")
def list_rules(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter rules by category (e.g. prompt_injection)."
    ),
):
    """List all available security rules and detection modules."""
    print_banner(version=__version__)
    rules = RuleRegistry.get_all()

    if category:
        rules = [r for r in rules if r.category.lower() == category.lower()]

    table = Table(title=f"LUME Security Rules ({len(rules)} Loaded)", border_style="bright_blue")
    table.add_column("Rule ID", style="bold yellow")
    table.add_column("Name", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Author", style="dim")

    if not rules:
        console.print("[yellow]No rules currently loaded in registry.[/yellow]")
        console.print("[dim]Security rules will be populated by Module 3 (Prompt Injection Rules).[/dim]\n")
        return

    for rule in rules:
        sev_style = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "dim white",
        }.get(rule.severity, "white")

        table.add_row(
            rule.rule_id,
            rule.name,
            rule.category,
            f"[{sev_style}]{rule.severity.value}[/{sev_style}]",
            rule.metadata.author,
        )

    console.print(table)


@app.command("scan")
def scan(
    target: str = typer.Option(
        ..., "--target", "-t", help="Target URL, model endpoint, or socket (e.g. http://localhost:8000/v1/chat)"
    ),
    module: str = typer.Option(
        "prompt_injection", "--module", "-m", help="Target security module to execute (default: prompt_injection)"
    ),
    rule_id: Optional[str] = typer.Option(
        None, "--rule", "-r", help="Specific rule ID to evaluate (e.g. PI-001)"
    ),
    concurrency: int = typer.Option(
        2, "--concurrency", "-c", min=1, max=10, help="Concurrent test execution limit"
    ),
    timeout: float = typer.Option(
        30.0, "--timeout", help="Per-rule timeout in seconds"
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output format: 'table' or 'json'"
    ),
):
    """Run an automated security scan against an AI target endpoint."""
    print_banner(version=__version__)

    console.print(
        Panel(
            Text.from_markup(
                f"[bold cyan]Initiating Security Scan[/bold cyan]\n"
                f"[bold]Target:[/bold] {target}\n"
                f"[bold]Module:[/bold] {module}\n"
                f"[bold]Concurrency:[/bold] {concurrency} | [bold]Timeout:[/bold] {timeout}s"
            ),
            border_style="cyan",
        )
    )

    rules = RuleRegistry.get_all()
    if module:
        rules = [r for r in rules if r.category.lower() == module.lower()]
    if rule_id:
        rules = [r for r in rules if r.rule_id.upper() == rule_id.upper()]

    if not rules:
        console.print(
            f"[bold yellow]Notice:[/bold yellow] No active rules loaded for module '{module}' "
            f"in the current build.\n"
            f"[dim]Module 3 (Prompt Injection Rules) will register the 6 standard rules.[/dim]"
        )
        return

    console.print(f"[green]Executing {len(rules)} rule(s) against target...[/green]")


@app.command("info")
def info():
    """Display environment diagnostics, Kali Linux, and Docker status."""
    print_banner(version=__version__)
    env_str = detect_environment()

    panel = Panel(
        Text.from_markup(
            f"[bold cyan]LUME Security Engine Diagnostics[/bold cyan]\n\n"
            f"• [bold]Version:[/bold] {__version__}\n"
            f"• [bold]Environment:[/bold] {env_str}\n"
            f"• [bold]Python:[/bold] {sys.version}\n"
            f"• [bold]OWASP LLM Target Scope:[/bold] LLM01 - Prompt Injection Scanner (v0.1.0)\n"
            f"• [bold]Architecture:[/bold] Modular 7-developer decouple contract\n"
        ),
        title="System Diagnostics",
        border_style="bright_blue",
    )
    console.print(panel)


if __name__ == "__main__":
    app()
