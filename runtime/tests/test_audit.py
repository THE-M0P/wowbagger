from __future__ import annotations

import json
from types import SimpleNamespace

from strix.core.hooks import _context_estimate_payload, _input_context_pressure, _usage_snapshot
from strix.report.audit import audit_path, configure_audit, preview, record_audit_event
from strix.tools.output_store import bound_text


def test_audit_events_are_written_as_jsonl(tmp_path) -> None:
    configure_audit(tmp_path)

    record_audit_event("tool_start", tool="exec_command", input_preview=preview("ls"))

    path = tmp_path / "audit.jsonl"
    assert audit_path() == path
    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["kind"] == "tool_start"
    assert event["tool"] == "exec_command"
    assert event["input_preview"]["text"] == "ls"

    configure_audit(None)


def test_preview_marks_truncation() -> None:
    result = preview("abcdef", max_chars=3)

    assert result == {"text": "abc", "chars": 6, "truncated": True}


def test_preview_bounds_structured_serialization() -> None:
    result = preview([{"content": "abcdef"}], max_chars=10)

    assert len(result["text"]) == 10
    assert result["chars"] > 10
    assert result["truncated"] is True


def test_output_truncation_writes_audit_event(tmp_path) -> None:
    configure_audit(tmp_path)

    result = bound_text("one\ntwo\nthree\nfour", max_lines=2, max_bytes=50)

    assert "truncated" in result
    event = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert event["kind"] == "tool_output_truncated"
    assert event["mode"] == "preview_only"
    assert event["dropped_lines"] > 0

    configure_audit(None)


def test_usage_snapshot_keeps_nested_details_queryable() -> None:
    usage = SimpleNamespace(
        requests=1,
        input_tokens=100,
        output_tokens=5,
        total_tokens=105,
        input_tokens_details=SimpleNamespace(cached_tokens=80, cache_write_tokens=0),
    )

    result = _usage_snapshot(usage)

    assert result["input_tokens_details"] == {"cached_tokens": 80, "cache_write_tokens": 0}


def test_input_context_pressure_uses_provider_input_tokens() -> None:
    usage = SimpleNamespace(input_tokens=65_325)

    assert _input_context_pressure(usage, 65_536) == 0.9968
    assert _input_context_pressure(usage, 0) is None
    assert _input_context_pressure(SimpleNamespace(input_tokens=None), 65_536) is None


def test_context_estimate_payload_is_bounded() -> None:
    text, truncated, chars = _context_estimate_payload(
        "system",
        [{"role": "user", "content": "abcdef"}],
        max_chars=12,
    )

    assert len(text) == 12
    assert truncated is True
    assert chars > 12
