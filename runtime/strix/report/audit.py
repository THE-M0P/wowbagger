"""Structured per-run audit event writer."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


AUDIT_FILENAME = "audit.jsonl"
_MAX_PREVIEW_CHARS = 2_000

_audit_path: Path | None = None
_lock = threading.Lock()


def configure_audit(run_dir: Path | None) -> None:
    global _audit_path  # noqa: PLW0603
    _audit_path = None if run_dir is None else run_dir / AUDIT_FILENAME


def audit_path() -> Path | None:
    return _audit_path


def preview(value: Any, *, max_chars: int = _MAX_PREVIEW_CHARS) -> dict[str, Any]:
    text, chars, truncated = _preview_text(value, max_chars=max_chars)
    return {"text": text, "chars": chars, "truncated": truncated}


def text_for_audit(value: Any) -> str:
    return _to_text(value)


def record_audit_event(kind: str, **fields: Any) -> None:
    path = _audit_path
    if path is None:
        return
    event = {
        "ts": datetime.now(UTC).isoformat(),
        "kind": kind,
        **fields,
    }
    line = json.dumps(event, ensure_ascii=False, default=str, sort_keys=True)
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _preview_text(value: Any, *, max_chars: int) -> tuple[str, int, bool]:
    if max_chars < 0:
        raise ValueError("max_chars must be non-negative")
    if isinstance(value, str):
        chars = len(value)
        return value[:max_chars], chars, chars > max_chars

    try:
        encoder = json.JSONEncoder(ensure_ascii=False, default=str, sort_keys=True)
        chunks: list[str] = []
        chars = 0
        truncated = False
        for chunk in encoder.iterencode(value):
            chunk_len = len(chunk)
            if chars + chunk_len > max_chars:
                keep = max(max_chars - chars, 0)
                if keep:
                    chunks.append(chunk[:keep])
                chars += chunk_len
                truncated = True
                break
            chunks.append(chunk)
            chars += chunk_len
        return "".join(chunks), chars, truncated
    except (TypeError, ValueError):
        text = str(value)
        chars = len(text)
        return text[:max_chars], chars, chars > max_chars
