import importlib
import os
import sys
import types

from strix.local_only import disable_agent_tracing


def test_agent_tracing_env_is_forced(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "0")
    monkeypatch.setenv("OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA", "1")
    monkeypatch.setitem(sys.modules, "agents", None)

    assert disable_agent_tracing() is False
    assert os.environ["OPENAI_AGENTS_DISABLE_TRACING"] == "1"
    assert os.environ["OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA"] == "0"


def test_agent_tracing_sdk_hook_is_called(monkeypatch) -> None:
    calls: list[bool] = []
    fake_agents = types.ModuleType("agents")
    fake_agents.set_tracing_disabled = calls.append
    monkeypatch.setitem(sys.modules, "agents", fake_agents)

    assert disable_agent_tracing() is True
    assert calls == [True]


def test_importing_strix_disables_agent_tracing(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "0")
    monkeypatch.setenv("OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA", "1")

    import strix

    importlib.reload(strix)

    assert os.environ["OPENAI_AGENTS_DISABLE_TRACING"] == "1"
    assert os.environ["OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA"] == "0"
