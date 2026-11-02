"""Main CLI entry point for LUME using Typer and Rich."""

import sys
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Ensure prompt_injection rules are loaded into the registry
import lume.modules.prompt_injection  # noqa: F401
from lume import __app_name__, __version__
from lume.adapters.http.client import HTTPTargetAdapter
from lume.cli.display.banner import detect_environment, get_console, print_banner, print_quick_start
from lume.core.rule_loader.base import RuleRegistry
from lume.core.scanner.runner import ScannerEngine, ScanOptions
from lume.core.target_manager.manager import (
    TargetAuthorizationError,
    TargetManager,
    TargetValidationError,
)
from lume.core.verdict.models import SeverityLevel
from lume.reporting.console_reporter import ConsoleReporter
from lume.reporting.html_reporter import HTMLReporter
from lume.reporting.json_reporter import JSONReporter
from lume.reporting.sarif_reporter import SARIFReporter

app = typer.Typer(
    name=__app_name__,
    help="LUME: Enterprise AI Security CLI Toolkit for LLM Vulnerability Assessment & Prompt Injection Scanning.",
    add_completion=False,
    no_args_is_help=False,
)

console = get_console()


def version_callback(value: bool):
    """Print version information and exit."""
    if value:
        console.print(f"[bold cyan]LUME-Security[/bold cyan] version [bold green]v{__version__}[/bold green]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
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
    if ctx.invoked_subcommand is None:
        print_banner(version=__version__)
        print_quick_start()
        raise typer.Exit(code=0)


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
    module: Optional[str] = typer.Argument(
        None, help="Target security module to execute (default: prompt_injection)"
    ),
    target: str = typer.Option(
        ..., "--target", "-t", help="Target URL, model endpoint, or socket (e.g. http://localhost:8000/v1/chat)"
    ),
    module_opt: Optional[str] = typer.Option(
        None, "--module", "-m", help="Alternative flag for security module (e.g. prompt_injection)"
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
        "table", "--output", "-o", help="Output format: table, json, sarif, or html"
    ),
    report_file: Optional[str] = typer.Option(
        None, "--report-file", help="Write the selected report format to this path"
    ),
    authorized: bool = typer.Option(
        False, "--authorized", "-a", help="Explicitly confirm authorization to test this target"
    ),
    headers: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom HTTP header (e.g. -H 'Authorization: Bearer token'). Can be specified multiple times.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Target model identifier if required by endpoint (e.g. gpt-4o, llama3)",
    ),
    payload_format: str = typer.Option(
        "standard",
        "--format",
        help="Request payload format: 'standard' ({prompt: text}) or 'openai' ({messages: [...]})",
    ),
    prompt_field: str = typer.Option(
        "prompt", "--prompt-field", help="JSON key to send prompt text to target endpoint"
    ),
    response_field: str = typer.Option(
        "response", "--response-field", help="JSON key to extract response text from target"
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        help="Upstream HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite or OWASP ZAP)",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        "-k",
        help="Disable TLS/SSL certificate verification (allow testing targets with self-signed certificates)",
    ),
    delay_ms: int = typer.Option(
        0,
        "--delay-ms",
        min=0,
        help="Rate-limiting delay between requests in milliseconds to prevent WAF bans",
    ),
    user_agent: Optional[str] = typer.Option(
        None,
        "--user-agent",
        help="Custom User-Agent header string to inject into request headers",
    ),
    cert: Optional[str] = typer.Option(
        None,
        "--cert",
        help="Path to client certificate PEM file for mTLS authentication",
    ),
):
    """Run an automated security scan against an authorized AI target endpoint."""
    report_format = output.lower()
    if report_format not in {"table", "json", "sarif", "html"}:
        console.print(f"[bold red]Invalid --output:[/bold red] {output}. Choose table, json, sarif, or html.")
        raise typer.Exit(code=2)
    print_banner(version=__version__)
    active_module = module or module_opt or "prompt_injection"
    active_module_norm = active_module.replace("-", "_").lower()

    # Parse headers for real client authentication
    parsed_headers = {}
    if headers:
        for h in headers:
            if ":" in h:
                hk, hv = h.split(":", 1)
                parsed_headers[hk.strip()] = hv.strip()

    verify_ssl = not insecure

    # 1. Target Validation & Authorization
    try:
        target_config = TargetManager.create_target_config(
            endpoint=target,
            adapter_type="http",
            timeout=timeout,
            headers=parsed_headers,
            model_name=model,
            authorized=authorized,
            proxy=proxy,
            verify=verify_ssl,
            cert=cert,
            delay_ms=delay_ms,
            user_agent=user_agent,
        )
        target_config.extra_params["prompt_field"] = prompt_field
        target_config.extra_params["response_field"] = response_field
        target_config.extra_params["payload_format"] = payload_format
    except TargetValidationError as exc:
        console.print(f"[bold red]Validation Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except TargetAuthorizationError as exc:
        console.print(f"[bold red]Authorization Error:[/bold red] {exc}")
        console.print("[yellow]Hint: Pass the '--authorized' flag if you have verified permission to test this target.[/yellow]")
        raise typer.Exit(code=1)

    # 2. Filter Rules
    rules = RuleRegistry.get_all()
    if active_module_norm:
        rules = [r for r in rules if r.category.lower() == active_module_norm]
    if rule_id:
        rules = [r for r in rules if r.rule_id.upper() == rule_id.upper()]

    if not rules:
        console.print(f"[bold yellow]Notice:[/bold yellow] No active rules loaded for module '{active_module}'.")
        raise typer.Exit(code=1)

    panel_lines = [
        "[bold cyan]Initiating Security Scan[/bold cyan]",
        f"[bold]Target:[/bold] {target_config.endpoint}",
        f"[bold]Module:[/bold] {active_module} ({len(rules)} rules loaded)",
        f"[bold]Concurrency:[/bold] {concurrency} | [bold]Timeout:[/bold] {timeout}s",
    ]
    if proxy:
        panel_lines.append(f"[bold]Proxy:[/bold] {proxy}")
    if insecure:
        panel_lines.append("[bold yellow]TLS Verification:[/bold yellow] [bold red]Disabled (--insecure)[/bold red]")
    if delay_ms > 0:
        panel_lines.append(f"[bold]Rate-Limiting Delay:[/bold] {delay_ms}ms")
    if user_agent:
        panel_lines.append(f"[bold]User-Agent:[/bold] {user_agent}")
    if cert:
        panel_lines.append(f"[bold]Client Cert:[/bold] {cert}")

    console.print(
        Panel(
            Text.from_markup("\n".join(panel_lines)),
            border_style="cyan",
        )
    )

    # 3. Initialize Adapter & Scanner Engine
    adapter = HTTPTargetAdapter(
        target_config,
        proxy=proxy,
        verify=verify_ssl,
        cert=cert,
        delay_ms=delay_ms,
        user_agent=user_agent,
    )
    engine = ScannerEngine(adapter)

    options = ScanOptions(
        target_name=target_config.endpoint,
        concurrency=concurrency,
        timeout_per_rule=timeout,
        proxy=proxy,
        verify=verify_ssl,
        cert=cert,
        delay_ms=delay_ms,
        user_agent=user_agent,
    )

    console.print("[dim]Executing security rules against target...[/dim]\n")
    report = engine.run_scan(rules=rules, options=options)

    # 4. Generate selected format. Table keeps the existing JSON sidecar behavior.
    if report_format == "sarif":
        saved_report_path = SARIFReporter().generate(report, file_path=report_file)
        console.print(f"[green]SARIF report saved:[/green] {saved_report_path}")
    elif report_format == "html":
        saved_report_path = HTMLReporter().generate(report, file_path=report_file)
        console.print(f"[green]HTML report saved:[/green] {saved_report_path}")
    else:
        json_reporter = JSONReporter()
        saved_report_path = json_reporter.generate(report, file_path=report_file)
        if report_format == "json":
            with open(saved_report_path, "r", encoding="utf-8") as f:
                console.print(f.read())
        else:
            console_reporter = ConsoleReporter(console)
            console_reporter.render_report(report)
            console.print(f"\n[dim]Report saved to:[/dim] [bold cyan]{saved_report_path}[/bold cyan]")
    # Scan finishes with code 0 (evaluation complete)
    raise typer.Exit(code=0)


@app.command("info")
def info():
    """Display environment diagnostics, Kali Linux, macOS, Windows, and Docker status."""
    print_banner(version=__version__)
    env_str = detect_environment()

    panel = Panel(
        Text.from_markup(
            f"[bold cyan]LUME Security Engine Diagnostics[/bold cyan]\n\n"
            f"• [bold]Version:[/bold] {__version__}\n"
            f"• [bold]Environment:[/bold] {env_str}\n"
            f"• [bold]Python:[/bold] {sys.version}\n"
            f"• [bold]Active Modules:[/bold] prompt_injection (6 rules loaded)\n"
            f"• [bold]OWASP LLM Target Scope:[/bold] LLM01:2025 - Prompt Injection Scanner (v1.0.0)\n"
            f"• [bold]Platform Support:[/bold] Kali Linux (Primary), macOS, Windows, Docker\n"
        ),
        title="System Diagnostics",
        border_style="bright_blue",
    )
    console.print(panel)


if __name__ == "__main__":
    app()
