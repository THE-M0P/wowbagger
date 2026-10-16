"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.llm.context_budget import context_window, count_tokens
from strix.report.audit import preview, record_audit_event
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse, TResponseInputItem


logger = logging.getLogger(__name__)


LLM_TURN_KEY = "llm_turn"
PROVIDER_INPUT_TOKENS_KEY = "provider_input_tokens"
PROVIDER_TOTAL_TOKENS_KEY = "provider_total_tokens"
PROVIDER_CONTEXT_PRESSURE_KEY = "provider_context_pressure"
# Persists across the _consume_provider_pressure pop so on_llm_start can read
# the server-reported pressure from the previous turn for wrap-up decisions.
PROVIDER_CONTEXT_PRESSURE_LAST_KEY = "provider_context_pressure_last"

_CONTEXT_ESTIMATE_MAX_CHARS = 500_000
_STAGE_LABELS: tuple[str, ...] = ("NOTICE", "URGENT", "CRITICAL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)
_SUBAGENT_BUDGET_RESERVE = 0.90


def _usage_snapshot(usage: Any) -> dict[str, Any]:
    if usage is None:
        return {}
    data: dict[str, Any] = {}
    for key in (
        "requests",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "input_tokens_details",
        "output_tokens_details",
    ):
        value = getattr(usage, key, None)
        if value is not None and not _is_mock_value(value):
            data[key] = _jsonable_usage_value(value)
    return data


def _input_context_pressure(usage: Any, model_context_window: int) -> float | None:
    if usage is None or not model_context_window:
        return None
    input_tokens = getattr(usage, "input_tokens", None)
    if not isinstance(input_tokens, int | float):
        return None
    return round(float(input_tokens) / model_context_window, 4)


def _is_mock_value(value: Any) -> bool:
    return type(value).__module__ == "unittest.mock"


def _jsonable_usage_value(value: Any) -> Any:
    if isinstance(value, str | int | float | bool) or value is None:
        result = value
    elif _is_mock_value(value):
        result = None
    elif isinstance(value, dict):
        result = {str(k): _jsonable_usage_value(v) for k, v in value.items()}
    elif isinstance(value, list | tuple):
        result = [_jsonable_usage_value(item) for item in value]
    elif callable(dump := getattr(value, "model_dump", None)):
        result = _jsonable_usage_value(dump())
    elif hasattr(value, "__dict__"):
        result = {
            str(k): _jsonable_usage_value(v)
            for k, v in vars(value).items()
            if not str(k).startswith("_")
        }
    else:
        result = str(value)
    return result


def _extract_thinking(response: Any) -> str | None:
    """Pull reasoning text out of ReasoningItems in response.output.

    The SDK converts reasoning_content from the API response into a ReasoningItem
    and filters it from context on the next turn — so it's available here but
    never injected back. We log it to audit so strix-watch can surface it."""
    for item in getattr(response, "output", None) or []:
        raw = getattr(item, "raw_item", item)
        if getattr(raw, "type", None) == "reasoning":
            for s in getattr(raw, "summary", None) or []:
                text = getattr(s, "text", None)
                if text:
                    return text
    return None


def _context_estimate_payload(
    system_prompt: str | None,
    input_items: list[Any],
    *,
    max_chars: int = _CONTEXT_ESTIMATE_MAX_CHARS,
) -> tuple[str, bool, int]:
    system = system_prompt or ""
    value = {"system_prompt": system, "input_items": input_items}
    payload = preview(value, max_chars=max_chars)
    return payload["text"], bool(payload["truncated"]), int(payload["chars"])


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class SubagentBudgetReservedError(RuntimeError):
    """Raised to stop a single sub-agent once the reserve threshold is crossed."""


class BudgetPausedError(RuntimeError):
    """Raised to park one agent when an interactive scan reaches its budget."""


def recomputed_budget_flags(
    cost: float,
    max_budget_usd: float | None,
    *,
    interactive: bool,
) -> tuple[bool, bool]:
    """Return the (budget_stopped, reserve_stopped) flags a resumed scan should carry."""
    if max_budget_usd is None:
        return False, False
    if interactive:
        return False, False
    budget_stopped = cost >= max_budget_usd
    reserve_stopped = cost >= max_budget_usd * _SUBAGENT_BUDGET_RESERVE
    return budget_stopped, reserve_stopped


def _crossed_stage(fraction: float, bands: tuple[float, ...]) -> int | None:
    crossed: int | None = None
    for index, band in enumerate(bands):
        if fraction >= band:
            crossed = index
    return crossed


_ROOT_DIRECTIVES: tuple[str, ...] = (
    (
        "As the root agent, begin planning your wind-down of the whole scan: avoid "
        "starting large new lines of investigation, and keep your required objectives on "
        "track so you can call finish_scan comfortably before the limit."
    ),
    (
        "As the root agent, prioritize wrapping up the whole scan now: stop opening new "
        "lines of investigation, close out only what is essential, and move toward calling "
        "finish_scan to compile and deliver the final report."
    ),
    (
        "As the root agent, STOP all other work on the whole scan and finish immediately: "
        "secure your findings and call finish_scan now — anything left unfinished when the "
        "limit is hit is discarded."
    ),
)
_SUBAGENT_DIRECTIVES: tuple[str, ...] = (
    (
        "As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, "
        "and if you are close to a confirmed, validated vulnerability, drive it to a result "
        "you can report."
    ),
    (
        "As a sub-agent, prioritize wrapping up your task now: report any confirmed, "
        "validated vulnerability, finish work that is nearly done rather than starting "
        "anything new, and prepare to call agent_finish."
    ),
    (
        "As a sub-agent, STOP all other work and finish immediately: report any confirmed "
        "vulnerability right now and call agent_finish to hand your results back to your "
        "parent before you are cut off."
    ),
)


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]], stage: int) -> str:
    is_root = context.context.get("parent_id") is None
    directives = _ROOT_DIRECTIVES if is_root else _SUBAGENT_DIRECTIVES
    return directives[stage]


def _urgency(stage: int) -> str:
    return _STAGE_LABELS[stage]


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage and warn/stop as turn and cost budgets are consumed."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        max_turns: int | None = None,
        interactive: bool = False,
        wrap_up_at_pressure: float | None = None,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        if max_turns is not None and max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._budget_increment = max_budget_usd
        self._max_turns = max_turns
        self._interactive = interactive
        self._wrap_up_at_pressure = wrap_up_at_pressure

    def extend_budget(self) -> None:
        if self._max_budget_usd is None or self._budget_increment is None:
            return
        self._max_budget_usd += self._budget_increment

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        context.context[LLM_TURN_KEY] = int(context.context.get(LLM_TURN_KEY, 0)) + 1
        ctx = context.context if isinstance(context.context, dict) else {}
        estimate_text, estimate_truncated, serialized_input_chars = _context_estimate_payload(
            system_prompt,
            input_items,
        )
        estimated_input_tokens = count_tokens(self._model, estimate_text)
        model_context_window = context_window(self._model)
        context_pressure = (
            round(estimated_input_tokens / model_context_window, 4)
            if model_context_window
            else None
        )
        # Prefer server-reported pressure from the previous turn (stored by on_llm_end
        # under a key that survives the _consume_provider_pressure pop). It captures
        # actual tokenisation + reasoning tokens that the client-side estimate misses.
        # The previous turn's input_tokens is a lower bound on this turn's input (this
        # turn adds the previous output on top), so max() is the safe combination.
        server_pressure_last = ctx.get(PROVIDER_CONTEXT_PRESSURE_LAST_KEY)
        effective_pressure = (
            max(context_pressure, float(server_pressure_last))
            if context_pressure is not None and isinstance(server_pressure_last, int | float)
            else context_pressure
        )
        record_audit_event(
            "llm_start",
            agent_id=ctx.get("agent_id"),
            agent_name=getattr(agent, "name", None),
            model=self._model,
            turn=context.context[LLM_TURN_KEY],
            system_prompt_chars=len(system_prompt or ""),
            input_items=len(input_items),
            estimated_input_tokens=estimated_input_tokens,
            context_estimate_truncated=estimate_truncated,
            context_estimate_chars=serialized_input_chars,
            context_estimate_max_chars=_CONTEXT_ESTIMATE_MAX_CHARS,
            context_window=model_context_window,
            context_pressure=context_pressure,
            server_context_pressure_last=server_pressure_last,
            effective_context_pressure=effective_pressure,
            input_preview=preview(input_items[-3:]),
        )
        try:
            self._maybe_warn_turns(context, input_items)
            self._maybe_warn_budget(context, input_items)
            self._maybe_warn_context_pressure(context, input_items, effective_pressure)
        except Exception:
            logger.exception("budget/turn warning injection failed")

    def _maybe_warn_turns(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if not self._max_turns:
            return
        usage = getattr(context, "usage", None)
        requests = getattr(usage, "requests", None)
        if not isinstance(requests, int):
            return
        turns_used = requests + 1
        stage = _crossed_stage(turns_used / self._max_turns, _TURN_WARN_BANDS)
        if stage is None:
            return
        remaining = max(self._max_turns - turns_used, 0)
        pct = round(100 * turns_used / self._max_turns)
        content = (
            f"[{_urgency(stage)}] Turn budget: {turns_used}/{self._max_turns} used ({pct}%). "
            f"About {remaining} turn(s) remain before this agent is force-stopped and any "
            f"in-progress work is discarded. {_wrapup_directive(context, stage)}"
        )
        input_items.append({"role": "user", "content": content})

    def _maybe_warn_budget(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._max_budget_usd is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        cost = report_state.get_total_llm_cost()
        is_root = context.context.get("parent_id") is None
        if self._interactive:
            bands = _ROOT_BUDGET_WARN_BANDS
        else:
            bands = _ROOT_BUDGET_WARN_BANDS if is_root else _SUBAGENT_BUDGET_WARN_BANDS
        stage = _crossed_stage(cost / self._max_budget_usd, bands)
        if stage is None:
            return
        pct = round(100 * cost / self._max_budget_usd)
        reserve_pct = round(_SUBAGENT_BUDGET_RESERVE * 100)
        if self._interactive:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached all agents are paused until the user chooses to continue. "
                f"{_wrapup_directive(context, stage)}"
            )
        elif is_root:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached the whole scan is stopped immediately, and sub-agents are stopped at "
                f"{reserve_pct}% to reserve the remainder for your final report. "
                f"{_wrapup_directive(context, stage)}"
            )
        else:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; "
                f"sub-agents are stopped at {reserve_pct}% to leave the remainder for the root "
                f"agent's final report. {_wrapup_directive(context, stage)}"
            )
        input_items.append({"role": "user", "content": content})

    def _maybe_warn_context_pressure(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
        estimated_pressure: float | None,
    ) -> None:
        if self._wrap_up_at_pressure is None or estimated_pressure is None:
            return
        if estimated_pressure < self._wrap_up_at_pressure:
            return
        pct = round(estimated_pressure * 100)
        deadline_pct = 95
        content = (
            f"[URGENT] Context pressure: {pct}% of the context window is now used. "
            f"Stop all exploration. You must complete your full findings report and call "
            f"the finish tool before pressure reaches {deadline_pct}% — write the report "
            f"now, you have several turns remaining but they must be spent on the report, "
            f"not further investigation. {_wrapup_directive(context, 1)}"
        )
        input_items.append({"role": "user", "content": content})

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        if report_state is None:
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"
        usage = getattr(response, "usage", None)
        model_context_window = context_window(self._model)
        input_pressure = _input_context_pressure(usage, model_context_window)
        input_tokens = getattr(usage, "input_tokens", None)
        total_tokens = getattr(usage, "total_tokens", None)
        if isinstance(input_tokens, int | float):
            ctx[PROVIDER_INPUT_TOKENS_KEY] = int(input_tokens)
        if isinstance(total_tokens, int | float):
            ctx[PROVIDER_TOTAL_TOKENS_KEY] = int(total_tokens)
        if input_pressure is not None:
            ctx[PROVIDER_CONTEXT_PRESSURE_KEY] = input_pressure
            ctx[PROVIDER_CONTEXT_PRESSURE_LAST_KEY] = input_pressure

        thinking = _extract_thinking(response)
        record_audit_event(
            "llm_end",
            agent_id=agent_id,
            agent_name=agent_name,
            model=self._model,
            turn=ctx.get(LLM_TURN_KEY),
            output_preview=preview(getattr(response, "output", None)),
            thinking=preview(thinking, max_chars=10_000_000) if thinking else None,
            usage=_usage_snapshot(usage),
            context_window=model_context_window,
            input_context_pressure=input_pressure,
        )

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)

        if self._max_budget_usd is not None:
            cost = report_state.get_total_llm_cost()
            if cost >= self._max_budget_usd:
                if self._interactive:
                    raise BudgetPausedError(
                        f"Scan budget of ${self._max_budget_usd:.2f} reached "
                        f"(spent ${cost:.4f}); pausing until the user continues"
                    )
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
            is_root = ctx.get("parent_id") is None
            if not self._interactive and not is_root:
                reserve_limit = self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
                if cost >= reserve_limit:
                    raise SubagentBudgetReservedError(
                        f"Sub-agent budget reserve reached: spent ${cost:.4f} of "
                        f"${self._max_budget_usd:.2f} "
                        f"(>= {round(_SUBAGENT_BUDGET_RESERVE * 100)}% reserve); stopping this "
                        "sub-agent so the root agent can finish the scan."
                    )
