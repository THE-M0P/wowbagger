"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from strix.config import loader
from strix.core.hooks import LLM_TURN_KEY
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from strix.tools.finish.tool import _coverage_summary, finish_scan


if TYPE_CHECKING:
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture(autouse=True)
def _empty_ledger(tmp_path: Path) -> None:
    hydrate_coverage_from_disk(tmp_path)


def _record(risk_area: str) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent() -> None:
    _record("SQL injection")

    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning() -> None:
    _record("SQL injection")
    _record("cross-site scripting")

    summary = _coverage_summary(_GRAPH)

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]


def test_reported_coverage_without_a_filed_report_is_surfaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area="object-level authorization",
        outcome="reported",
        evidence="Confirmed cross-tenant read. Filed as vuln-9999.",
        agent_id="agent-1",
        agent_name="authz-tester",
    )
    monkeypatch.setattr("strix.tools.coverage.tools._filed_report_ids", set)

    summary = _coverage_summary(_GRAPH)

    assert len(summary["unfiled_reported_surfaces"]) == 1
    assert "reported coverage" in summary["coverage_report_warning"]


@pytest.mark.asyncio
async def test_finish_scan_can_be_blocked_until_minimum_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_MIN_FINISH_TURNS", "200")
    monkeypatch.setattr(loader, "_cached", None)
    ctx = ToolContext(
        context={"agent_id": "root", "parent_id": None, LLM_TURN_KEY: 73},
        tool_name="finish_scan",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    result = await finish_scan.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "executive_summary": "x",
                "methodology": "x",
                "technical_analysis": "x",
                "recommendations": "x",
            }
        ),
    )

    parsed = json.loads(result)
    assert parsed["success"] is False
    assert parsed["scan_completed"] is False
    assert parsed["current_turn"] == 73
    assert parsed["min_finish_turns"] == 200
    assert "disabled until turn 200" in parsed["error"]
    monkeypatch.setattr(loader, "_cached", None)


@pytest.mark.asyncio
async def test_finish_scan_rejects_oversized_final_fields() -> None:
    ctx = ToolContext(
        context={"agent_id": "root", "parent_id": None, LLM_TURN_KEY: 201},
        tool_name="finish_scan",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    result = await finish_scan.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "executive_summary": "x" * 2_000,
                "methodology": "x",
                "technical_analysis": "x",
                "recommendations": "x",
            }
        ),
    )

    parsed = json.loads(result)
    assert parsed["success"] is False
    assert any("too long" in error for error in parsed["errors"])
