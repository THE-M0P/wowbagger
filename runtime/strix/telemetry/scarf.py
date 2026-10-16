"""No-op Scarf compatibility shim for the DeepThought fork."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.report.state import ReportState


def _send(event: str, properties: dict[str, Any]) -> bool:
    return False


def start(
    model: str | None,
    scan_mode: str | None,
    is_whitebox: bool,
    interactive: bool,
    has_instructions: bool,
    auth_mode: str | None = None,
) -> None:
    return None


def finding(severity: str, cwe: str | None = None, is_cve: bool = False) -> None:
    return None


def skill_loaded(skill_name: str) -> None:
    return None


def end(report_state: ReportState, exit_reason: str = "completed") -> None:
    report_state.scarf_scan_ended_sent = False


def error(error_type: str) -> None:
    return None
