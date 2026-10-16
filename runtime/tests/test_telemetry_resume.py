from typing import Any

import pytest

from strix.telemetry import posthog, scarf


class DummyReportState:
    posthog_scan_ended_sent = True
    scarf_scan_ended_sent = True


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_telemetry_modules_are_noop(telemetry: Any) -> None:
    state = DummyReportState()
    assert telemetry._send("event", {"field": "value"}) is False
    telemetry.start(
        model="ollama/model",
        scan_mode="quick",
        is_whitebox=True,
        interactive=False,
        has_instructions=True,
    )
    telemetry.finding("high", cwe="CWE-79", is_cve=False)
    telemetry.skill_loaded("sql_injection")
    telemetry.end(state)
    telemetry.error("example")
