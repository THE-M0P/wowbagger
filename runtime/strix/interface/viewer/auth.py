"""Viewer local auth state.

Remote OTP, report delivery, and feedback relay calls are disabled in the
DeepThought fork. State helpers remain for local viewer compatibility.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.utils.secret_files import write_secret_text


logger = logging.getLogger(__name__)

AUTH_PATH = Path.home() / ".strix" / "viewer-auth.json"

_OTP_TIMEOUT = 15
_SEND_TIMEOUT = 30


class RelayError(Exception):
    """A relay call failed. ``code`` is a stable, machine-readable reason."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


# --- local state ------------------------------------------------------------


def read_auth() -> dict[str, Any] | None:
    """Return the stored ``{email, token, verified_at}`` record, or None."""
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    email = data.get("email")
    token = data.get("token")
    if not isinstance(email, str) or not email or not isinstance(token, str) or not token:
        return None
    return data


def parse_expiry(raw: object) -> datetime | None:
    """Parse a relay ``expires_at`` value into an aware UTC datetime.

    Accepts both ISO 8601 strings and epoch seconds (as a number or numeric
    string) so a valid relay expiry is not misread as missing. Returns None only
    when it is genuinely absent or unparseable; both the local gate (see
    ``is_verified``) and OTP verification (see ``otp_verify``) fail closed on such
    values, matching the relay, which rejects a token with no valid expiry.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int | float):
        return _from_epoch(raw)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return _from_epoch(float(raw))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _expiry(record: dict[str, Any]) -> datetime | None:
    """The stored ``verified_at`` parsed to a datetime, or None if unusable."""
    return parse_expiry(record.get("verified_at"))


def _from_epoch(seconds: float) -> datetime | None:
    """Epoch seconds → aware UTC datetime, or None if out of range."""
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def is_verified() -> bool:
    """True when a usable email + token record with a valid future expiry exists.

    The expiry returned by OTP verification is enforced here so history stops
    unlocking once the token lapses. It fails closed: a record whose expiry is
    absent, blank, or unparseable requires re-verification rather than unlocking
    forever, keeping the local gate in step with the relay (which rejects an
    expired token on report send).
    """
    record = read_auth()
    if record is None:
        return False
    expiry = _expiry(record)
    return expiry is not None and expiry > datetime.now(UTC)


def write_auth(email: str, token: str, verified_at: str) -> None:
    """Atomically persist the auth record with 0600 permissions."""
    payload = json.dumps({"email": email, "token": token, "verified_at": verified_at})
    write_secret_text(AUTH_PATH, payload)


def forget() -> None:
    """Delete the stored auth record. No-op if it is absent."""
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


# --- disabled relay client --------------------------------------------------


def otp_start(email: str) -> None:
    """Remote OTP is disabled in this fork."""
    raise RelayError("local_only")


def otp_verify(email: str, code: str) -> dict[str, Any]:
    """Remote OTP is disabled in this fork."""
    raise RelayError("local_only")


def feedback_submit(email: str, message: str) -> None:
    """Remote feedback is disabled in this fork."""
    raise RelayError("local_only")


def report_send(
    token: str,
    pdf_bytes: bytes,
    filename: str,
    run_name: str,
    target: str,
) -> None:
    """Remote report delivery is disabled in this fork."""
    raise RelayError("local_only")


__all__ = [
    "AUTH_PATH",
    "RelayError",
    "feedback_submit",
    "forget",
    "is_verified",
    "otp_start",
    "otp_verify",
    "read_auth",
    "report_send",
    "write_auth",
]
