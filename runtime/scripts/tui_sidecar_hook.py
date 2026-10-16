"""Hatch build hook: bundle the compiled Go TUI sidecar into platform wheels.

Editable installs and sdists skip the build. For wheels, the sidecar is built
with `go` (or taken from build/sidecar/ if already present) and force-included
as strix/bin/strix-tui.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class TuiSidecarHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel" or version == "editable":
            return

        suffix = ".exe" if sys.platform == "win32" else ""
        root = Path(self.root)
        binary = root / "build" / "sidecar" / f"strix-tui{suffix}"

        if not binary.exists():
            go = shutil.which("go")
            if go is None:
                self.app.display_warning("go not found; building wheel without the TUI sidecar")
                return
            binary.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(  # noqa: S603
                [go, "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), "./cmd/strix-tui"],
                cwd=root / "strix" / "interface" / "tui",
                env={**os.environ, "CGO_ENABLED": "0"},
                check=True,
            )

        build_data["pure_python"] = False
        build_data["infer_tag"] = True
        build_data["force_include"][str(binary)] = f"strix/bin/strix-tui{suffix}"
