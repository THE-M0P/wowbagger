"""Tests for local viewer auth state and disabled relay calls."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from strix.interface.viewer import auth


if TYPE_CHECKING:
    from pathlib import Path


def _iso(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).isoformat()


@pytest.fixture(autouse=True)
def _tmp_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setattr(auth, "AUTH_PATH", home / ".strix" / "viewer-auth.json")
    return auth.AUTH_PATH


def test_write_read_forget_roundtrip() -> None:
    assert auth.read_auth() is None
    assert auth.is_verified() is False

    auth.write_auth(email="user@example.com", token="tok-123", verified_at=_iso(timedelta(days=30)))  # nosec B106

    record = auth.read_auth()
    assert record is not None
    assert record["email"] == "user@example.com"
    assert record["token"] == "tok-123"
    assert auth.is_verified() is True

    auth.forget()
    assert auth.read_auth() is None
    assert auth.is_verified() is False
    auth.forget()


def test_is_verified_enforces_expiry() -> None:
    auth.write_auth(email="a@b.com", token="t", verified_at=_iso(timedelta(hours=-1)))  # nosec B106
    assert auth.read_auth() is not None
    assert auth.is_verified() is False

    auth.write_auth(email="a@b.com", token="t", verified_at=_iso(timedelta(hours=1)))  # nosec B106
    assert auth.is_verified() is True


def test_is_verified_fails_closed_when_expiry_absent_or_unparseable() -> None:
    auth.write_auth(email="a@b.com", token="t", verified_at="")  # nosec B106
    assert auth.read_auth() is not None
    assert auth.is_verified() is False

    auth.write_auth(email="a@b.com", token="t", verified_at="not-a-date")  # nosec B106
    assert auth.is_verified() is False


def test_is_verified_accepts_epoch_expiry() -> None:
    future = (datetime.now(UTC) + timedelta(hours=1)).timestamp()
    past = (datetime.now(UTC) - timedelta(hours=1)).timestamp()

    auth.write_auth(email="a@b.com", token="t", verified_at=str(future))  # nosec B106
    assert auth.is_verified() is True
    auth.write_auth(email="a@b.com", token="t", verified_at=str(past))  # nosec B106
    assert auth.is_verified() is False

    auth.AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.AUTH_PATH.write_text(
        f'{{"email": "a@b.com", "token": "t", "verified_at": {future}}}', encoding="utf-8"
    )
    assert auth.is_verified() is True


def test_write_auth_is_0600() -> None:
    auth.write_auth(email="a@b.com", token="t", verified_at="")  # nosec B106
    mode = stat.S_IMODE(auth.AUTH_PATH.stat().st_mode)
    assert mode == 0o600


def test_read_auth_rejects_incomplete_record() -> None:
    auth.AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.AUTH_PATH.write_text('{"email": "a@b.com"}', encoding="utf-8")
    assert auth.read_auth() is None
    assert auth.is_verified() is False


@pytest.mark.parametrize(
    "call",
    [
        lambda: auth.otp_start("a@b.com"),
        lambda: auth.otp_verify("a@b.com", "123456"),
        lambda: auth.feedback_submit("a@b.com", "hello"),
        lambda: auth.report_send("tok", b"%PDF-fake", "report.pdf", "run", "target"),
    ],
)
def test_remote_relay_calls_are_disabled(call) -> None:
    with pytest.raises(auth.RelayError) as exc:
        call()
    assert exc.value.code == "local_only"
