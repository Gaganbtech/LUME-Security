import os
import platform
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Ensure UTF-8 output streams on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(legacy_windows=False)


def get_console() -> Console:
    """Return the global Rich console instance."""
    return console


def detect_environment() -> str:
    """Detect execution environment (Kali Linux, Docker, macOS, Windows, Linux)."""
    env_flags = []

    # Check for Docker
    if os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER"):
        env_flags.append("[bold cyan]Docker[/bold cyan]")

    system_name = platform.system()
    machine_arch = platform.machine()

    # Check for Kali Linux specifically
    is_kali = False
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                content = f.read().lower()
                if "kali" in content:
                    is_kali = True
                    env_flags.append("[bold red]Kali Linux[/bold red]")
    except Exception:
        pass

    if not is_kali:
        if system_name == "Darwin":
            mac_ver = platform.mac_ver()[0] or "macOS"
            env_flags.append(f"[bold green]macOS {mac_ver}[/bold green] ({machine_arch})")
        elif system_name == "Windows":
            win_ver = platform.release()
            env_flags.append(f"[bold blue]Windows {win_ver}[/bold blue] ({machine_arch})")
        elif system_name == "Linux":
            env_flags.append(f"[bold magenta]Linux[/bold magenta] ({machine_arch})")
        else:
            env_flags.append(f"[dim]{system_name} ({machine_arch})[/dim]")

    return " | ".join(env_flags)


def print_banner(version: str = "0.1.0") -> None:
    """Print the professional LUME AI Security enterprise banner."""
    ascii_art = """
 ██╗     ██╗   ██╗███╗   ███╗███████╗     █████╗ ██╗
 ██║     ██║   ██║████╗ ████║██╔════╝    ██╔══██╗██║
 ██║     ██║   ██║██╔████╔██║█████╗      ███████║██║
 ██║     ██║   ██║██║╚██╔╝██║██╔══╝      ██╔══██║██║
 ███████╗╚██████╔╝██║ ╚═╝ ██║███████╗    ██║  ██║██║
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝
    S E C U R I T Y   T O O L K I T   [ E N T E R P R I S E ]
"""
    banner_text = Text()
    banner_text.append(ascii_art, style="bold cyan")
    banner_text.append("\n  Enterprise AI Security & Prompt Injection Assessment Engine", style="bold white")
    banner_text.append(
        "\n  Aligned with OWASP Top 10 for LLM (2025) • Offensive & Defensive Testing\n\n",
        style="dim cyan",
    )

    banner_text.append(" [ v" + version + " ] ", style="bold black on bright_cyan")
    banner_text.append(" [ 6 RULES ACTIVE ] ", style="bold black on bright_green")
    banner_text.append(" [ OWASP LLM01:2025 ] ", style="bold black on bright_yellow")
    banner_text.append(" [ ENTERPRISE ]\n", style="bold black on bright_magenta")

    env_info = detect_environment()

    panel = Panel(
        banner_text,
        subtitle=f"Environment: {env_info}",
        subtitle_align="right",
        border_style="bright_blue",
        padding=(0, 2),
    )
    console.print(panel)


def print_quick_start() -> None:
    """Print quick start guidance and core commands table."""
    table = Table(
        title="LUME Security Command Center",
        border_style="bright_blue",
        title_style="bold bright_white",
    )
    table.add_column("Command", style="bold yellow", width=14)
    table.add_column("Purpose", style="bold white", width=32)
    table.add_column("Syntax & Example", style="cyan")

    table.add_row(
        "scan",
        "Run security assessment scan",
        "lume scan prompt-injection --target http://localhost:8000/v1/chat",
    )
    table.add_row(
        "list-rules",
        "Display loaded detection rules",
        "lume list-rules [--category prompt_injection]",
    )
    table.add_row(
        "info",
        "System diagnostics & OS status",
        "lume info",
    )
    table.add_row(
        "version",
        "View engine version details",
        "lume version [--verbose]",
    )
    table.add_row(
        "demo",
        "One-touch local verification",
        "./scripts/demo_scan.sh",
    )

    console.print(table)
    console.print(
        "\n[bold green]Quick Start Tip:[/bold green] [dim]Run[/dim] "
        "[bold cyan]lume scan --target <URL>[/bold cyan] [dim]or pass[/dim] "
        "[bold cyan]--help[/bold cyan] [dim]to any command for full flags.[/dim]\n"
    )
