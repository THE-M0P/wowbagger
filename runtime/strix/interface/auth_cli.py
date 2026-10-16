"""Disabled remote subscription auth for the DeepThought fork."""

from __future__ import annotations

from rich.console import Console


LOGIN_PROVIDER = "chatgpt"
_ACCEPTED_PROVIDERS = frozenset({LOGIN_PROVIDER, "codex"})

_USAGE = "Usage:\n  strix auth status\n  strix auth logout"


def run_auth(argv: list[str]) -> int:
    console = Console()
    subcommand = argv[0] if argv else "status"

    if subcommand in ("-h", "--help", "help"):
        console.print(_USAGE)
        return 0
    if subcommand == "logout":
        console.print("Remote subscription auth is disabled in this local-only fork.")
        return 0
    if subcommand == "status":
        console.print("Remote subscription auth is disabled in this local-only fork.")
        return 1
    if subcommand == "login":
        console.print("Remote subscription auth is disabled in this local-only fork.")
        return 2

    console.print(f"[red]Unknown auth command:[/] {subcommand}\n")
    console.print(_USAGE)
    return 2
