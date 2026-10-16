"""Local-only runtime guards."""

from __future__ import annotations

import os


def disable_agent_tracing() -> bool:
    """Disable OpenAI Agents SDK trace export for this process.

    Returns ``True`` when the SDK hook was available and called. Environment
    variables are always forced so child imports and subprocesses inherit the
    local-only default.
    """
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
    os.environ["OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA"] = "0"

    try:
        from agents import set_tracing_disabled
    except (ImportError, AttributeError):
        return False

    set_tracing_disabled(True)
    return True
