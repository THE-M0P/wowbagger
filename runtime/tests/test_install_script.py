from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="scripts/install.sh is a POSIX shell installer",
)


def _create_mock_commands(tmp_path: Path) -> tuple[Path, Path]:
    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    curl_log_path = tmp_path / "curl.log"
    curl = mock_bin / "curl"
    curl.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$STRIX_TEST_CURL_LOG"
exit 1
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    return mock_bin, curl_log_path


def test_installer_is_local_only_and_does_not_download(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    mock_bin, curl_log_path = _create_mock_commands(tmp_path)
    home_path = tmp_path / "home"
    home_path.mkdir()
    environment = {
        "HOME": str(home_path),
        "XDG_CONFIG_HOME": str(home_path / ".config"),
        "PATH": f"{mock_bin}:/usr/bin:/bin",
        "SHELL": "/bin/bash",
        "STRIX_TEST_CURL_LOG": str(curl_log_path),
    }

    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(repository_root / "scripts/install.sh")],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "DeepThought is configured for local-only use." in result.stdout
    assert "uv sync" in result.stdout
    assert "./scripts/docker.sh" in result.stdout
    assert "deepthought-sandbox:local" in result.stdout
    assert not curl_log_path.exists()
    assert not (home_path / ".strix").exists()
