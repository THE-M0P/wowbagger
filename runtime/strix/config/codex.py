"""Local-only subscription-auth compatibility helpers.

The DeepThought fork does not support remote subscription OAuth. Model traffic
is routed only through the model provider explicitly configured by the operator.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from openai import AsyncOpenAI


PROVIDER = "codex"
SUBSCRIPTION_PREFIX = "chatgpt/"


class CodexAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


class CodexContentGuardrailError(Exception):
    def __init__(self, model: str, original: BaseException | None = None) -> None:
        self.model = model
        self.original = original
        super().__init__(f"'{model}' was refused by a remote provider guardrail.")


def read_record() -> dict[str, Any] | None:
    return None


def is_authenticated() -> bool:
    return False


def save_record(record: dict[str, Any]) -> None:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def logout() -> None:
    return None


def generate_pkce() -> tuple[str, str]:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def create_state() -> str:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def build_authorize_url(challenge: str, state: str) -> str:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def parse_redirect_input(value: str) -> tuple[str | None, str | None]:
    return None, None


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def refresh_access_token(record: dict[str, Any]) -> dict[str, Any]:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def get_subscription_client() -> AsyncOpenAI:
    raise CodexAuthError(
        "local_only",
        "Remote subscription auth is disabled in the DeepThought local-only fork.",
    )


def subscription_model(model_name: str | None) -> str | None:
    return None


def auth_mode(model_name: str | None) -> str:
    return "api_key"


def is_content_guardrail_error(exc: BaseException) -> bool:
    if isinstance(exc, CodexContentGuardrailError):
        return True
    text = str(exc).lower()
    guardrail_markers = (
        "content was flagged",
        "possible cybersecurity risk",
        "content policy",
    )
    return any(marker in text for marker in guardrail_markers)
