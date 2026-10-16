from strix.config import codex
from strix.interface import auth_cli


def test_auth_cli_reports_local_only() -> None:
    assert auth_cli.run_auth(["--help"]) == 0
    assert auth_cli.run_auth(["status"]) == 1
    assert auth_cli.run_auth(["logout"]) == 0
    assert auth_cli.run_auth(["login", "chatgpt"]) == 2


def test_subscription_models_are_disabled() -> None:
    assert codex.subscription_model("chatgpt/gpt-5") is None
    assert codex.auth_mode("chatgpt/gpt-5") == "api_key"
    assert codex.is_authenticated() is False
