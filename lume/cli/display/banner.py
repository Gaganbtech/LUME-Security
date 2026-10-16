"""Terminal banners, styling, and Rich console helpers for LUME."""

import os
import platform

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def get_console() -> Console:
    """Return the global Rich console instance."""
    return console


def detect_environment() -> str:
    """Detect if running inside Docker or Kali Linux."""
    env_flags = []
    if os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER"):
        env_flags.append("[bold cyan]Docker[/bold cyan]")

    # Check for Kali Linux
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                if "kali" in content:
                    env_flags.append("[bold red]Kali Linux[/bold red]")
    except Exception:
        pass

    if not env_flags:
        env_flags.append(f"[dim]{platform.system()} ({platform.machine()})[/dim]")

    return " | ".join(env_flags)


def print_banner(version: str = "0.1.0") -> None:
    """Print the LUME ASCII art banner and system context."""
    ascii_art = """
 ██╗     ██╗   ██╗███╗   ███╗███████╗
 ██║     ██║   ██║████╗ ████║██╔════╝
 ██║     ██║   ██║██╔████╔██║█████╗
 ██║     ██║   ██║██║╚██╔╝██║██╔══╝
 ███████╗╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
"""
    banner_text = Text()
    banner_text.append(ascii_art, style="bold cyan")
    banner_text.append("\n  Enterprise AI Security & Prompt Injection CLI Toolkit", style="bold white")
    banner_text.append(f"\n  v{version} | OWASP Top 10 for LLM Assessment\n", style="dim")

    env_info = detect_environment()

    panel = Panel(
        banner_text,
        subtitle=f"Environment: {env_info}",
        subtitle_align="right",
        border_style="bright_blue",
        padding=(0, 2),
    )
    console.print(panel)
