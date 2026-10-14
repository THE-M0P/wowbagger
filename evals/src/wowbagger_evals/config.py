"""Central configuration for wowbagger-evals.

Priority order for every path: CLI flag > env var > config file > auto-detect > last-resort default.

Config file location: ~/.config/wowbagger-evals/config.toml
Copy config.example.toml (repo root) there and fill in 4 lines to make this portable.
"""
from __future__ import annotations

import os
import shutil
import tomllib
from pathlib import Path

_CONFIG_PATH = Path.home() / ".config" / "wowbagger-evals" / "config.toml"


def _load_config_file() -> dict:
    if _CONFIG_PATH.is_file():
        try:
            with open(_CONFIG_PATH, "rb") as f:
                return tomllib.load(f)
        except Exception:
            pass
    return {}


_cfg = _load_config_file()


def _resolve(env_var: str, config_key: str) -> Path | None:
    if v := os.environ.get(env_var):
        return Path(v).expanduser()
    if v := _cfg.get(config_key):
        return Path(str(v)).expanduser()
    return None


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


# ---------------------------------------------------------------------------
# Resolved defaults — used as fallbacks when CLI flags are not provided
# ---------------------------------------------------------------------------

STRIX_BIN: Path | None = (
    _resolve("STRIX_BIN", "strix")
    or _which("strix")
)

# Auto-detect specialists/ from the cloned repo layout when installed in editable mode.
# __file__ = <repo>/evals/src/wowbagger_evals/config.py
# → .parent×3 = evals/  → .parent = repo root  → repo root / "specialists"
_repo_specialists: Path | None = None
_candidate = Path(__file__).parent.parent.parent.parent / "specialists"
if _candidate.is_dir():
    _repo_specialists = _candidate

SPECIALIST_PACK: Path | None = (
    _resolve("ENGAGE_SPECIALIST_PACK", "specialist_pack")
    or (_repo_specialists / "bug-bounty" if _repo_specialists else None)
)

# Smoke-test pack — must contain profiles/smoke-test.md.
SMOKE_SPECIALIST_PACK: Path | None = (
    _resolve("ENGAGE_SMOKE_SPECIALIST_PACK", "smoke_specialist_pack")
    or (_repo_specialists / "multi-specialist" if _repo_specialists else None)
)

TARGET_SPECIALIST_PACK: Path | None = (
    _resolve("ENGAGE_TARGET_SPECIALIST_PACK", "target_specialist_pack")
    or _resolve("ENGAGE_H1_SPECIALIST_PACK", "h1_specialist_pack")  # legacy alias
    or (_repo_specialists / "bug-bounty-target" if _repo_specialists else None)
)

# The evals repo itself — used only for git commit recording in manifests.
# Auto-detects from __file__ so it works anywhere the package is installed.
EVALS_REPO_DIR: Path = (
    _resolve("ENGAGE_EVALS_REPO", "evals_repo_dir")
    or Path(__file__).parent.parent.parent  # src/wowbagger_evals/ → src/ → repo root
)

# Default Docker sandbox image. Set ENGAGE_SANDBOX_IMAGE or config sandbox_image
# so you don't have to pass --sandbox-image on every invocation.
SANDBOX_IMAGE: str | None = (
    os.environ.get("ENGAGE_SANDBOX_IMAGE")
    or (str(_cfg["sandbox_image"]) if "sandbox_image" in _cfg else None)
)

# LLM settings — set in config.toml or env vars to avoid repeating on every invocation.
# Claude models need the anthropic/ prefix (e.g. anthropic/claude-haiku-4-5-20251001).
LLM: str | None = os.environ.get("STRIX_LLM") or _cfg.get("llm")
LLM_API_BASE: str | None = os.environ.get("LLM_API_BASE") or _cfg.get("llm_api_base")
LLM_API_KEY: str | None = os.environ.get("LLM_API_KEY") or _cfg.get("llm_api_key")
CONTEXT_WINDOW: int | None = (
    (int(os.environ["STRIX_CONTEXT_WINDOW_TOKENS"]) if "STRIX_CONTEXT_WINDOW_TOKENS" in os.environ else None)
    or (int(_cfg["context_window"]) if "context_window" in _cfg else None)
)
DISABLE_STREAMING: bool = (
    os.environ.get("ENGAGE_DISABLE_STREAMING", "").lower() in ("1", "true", "yes")
    or bool(_cfg.get("disable_streaming", False))
)

# Turn limits and context wrap-up — set once in config rather than repeating on every invocation.
EXPLORE_TURNS: int = int(os.environ.get("ENGAGE_EXPLORE_TURNS") or _cfg.get("explore_turns") or 50)
AUDIT_TURNS: int = int(os.environ.get("ENGAGE_AUDIT_TURNS") or _cfg.get("audit_turns") or 40)
WRAP_UP_AT_PRESSURE: float | None = (
    (float(os.environ["ENGAGE_WRAP_UP_AT_PRESSURE"]) if "ENGAGE_WRAP_UP_AT_PRESSURE" in os.environ else None)
    or (float(_cfg["wrap_up_at_pressure"]) if "wrap_up_at_pressure" in _cfg else None)
)
