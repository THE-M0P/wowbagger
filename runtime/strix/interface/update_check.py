"""Local-only update policy for the DeepThought fork.

This fork never checks PyPI, GitHub, or project servers for updates at runtime.
Updates are handled explicitly by fetching the configured upstream remote.
"""

from __future__ import annotations

from rich.console import Console


def is_binary_install() -> bool:
    return False


def get_install_method() -> str:
    return "source"


def get_upgrade_command(method: str | None = None) -> str:
    return "git fetch upstream && git merge --ff-only upstream/main"


def start_background_check() -> None:
    return None


def get_available_update(*, respect_skip: bool = True) -> str | None:
    return None


def notify_update(console: Console) -> None:
    return None


def prompt_update_if_available(console: Console) -> bool:
    return False


def self_update(console: Console | None = None, version: str | None = None) -> bool:
    console = console or Console()
    console.print(
        "[yellow]Self-update is disabled in this local-only fork.[/] "
        "Update deliberately with: [cyan]git fetch upstream && git merge --ff-only upstream/main[/]"
    )
    return False
