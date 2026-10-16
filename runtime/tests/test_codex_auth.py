import pytest

from strix.config import codex


def test_subscription_auth_is_local_only() -> None:
    assert codex.read_record() is None
    assert codex.is_authenticated() is False
    assert codex.subscription_model("chatgpt/gpt-5") is None
    assert codex.auth_mode("chatgpt/gpt-5") == "api_key"


@pytest.mark.parametrize(
    "call",
    [
        lambda: codex.generate_pkce(),
        lambda: codex.create_state(),
        lambda: codex.build_authorize_url("challenge", "state"),
        lambda: codex.exchange_code("code", "verifier"),
        lambda: codex.refresh_access_token({}),
        lambda: codex.get_subscription_client(),
        lambda: codex.save_record({}),
    ],
)
def test_remote_subscription_calls_are_disabled(call) -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        call()
    assert exc.value.code == "local_only"


def test_parse_redirect_input_is_disabled() -> None:
    assert codex.parse_redirect_input("code=AAA&state=BBB") == (None, None)


def test_content_guardrail_error_type_is_preserved() -> None:
    err = codex.CodexContentGuardrailError("remote-model")
    assert codex.is_content_guardrail_error(err) is True
    assert (
        codex.is_content_guardrail_error(
            RuntimeError("This content was flagged for possible cybersecurity risk.")
        )
        is True
    )
    assert codex.is_content_guardrail_error(RuntimeError("rate limit exceeded")) is False
