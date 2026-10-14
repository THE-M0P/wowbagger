from __future__ import annotations

import json
from pathlib import Path

import pytest

from wowbagger_evals.bountybench import (
    BountyBenchError,
    COMPACT_PROFILE_RELATIVE_PATHS,
    build_instruction,
    build_plan,
    collect_exploit_artifact,
    load_task,
    normalize_target_host,
    resolve_bountytasks_root,
    stable_manifest_hash,
    write_plan,
)


def make_bountybench(root: Path) -> Path:
    task = root / "bountytasks" / "demo"
    bounty = task / "bounties" / "bounty_0"
    codebase = task / "codebase"
    codebase.mkdir(parents=True)
    (codebase / "app.py").write_text("print('demo')\n", encoding="utf-8")
    (task / "app.py").write_text("print('public harness')\n", encoding="utf-8")
    (task / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (task / "run_repo_invariants.sh").write_text("hidden-ish invariant\n", encoding="utf-8")
    (task / "metadata.json").write_text(
        json.dumps({"target_host": "demo-app:8000"}),
        encoding="utf-8",
    )
    bounty.mkdir(parents=True)
    (bounty / "bounty_metadata.json").write_text(
        json.dumps(
            {
                "CWE": "CWE-999",
                "CVE": "CVE-2099-0001",
                "severity": "critical",
                "bounty_link": "https://example.invalid/hidden",
                "vulnerable_commit": "secret-commit",
                "patch": {"patch_files/secret.patch": "codebase/app.py"},
            }
        ),
        encoding="utf-8",
    )
    return root


def test_exploit_info_staged_in_instructions(tmp_path: Path) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    # Add exploit_info to the bounty_metadata
    bounty_meta = root / "bountytasks" / "demo" / "bounties" / "bounty_0" / "bounty_metadata.json"
    data = json.loads(bounty_meta.read_text())
    data["exploit_info"] = "username: test_user@exploit.com, password: hunter2."
    bounty_meta.write_text(json.dumps(data), encoding="utf-8")

    task = load_task(root, "demo", 0, "detect")
    plan = build_plan(task, strix=Path("/usr/local/bin/strix"), output_dir=tmp_path / "run")
    instruction = build_instruction(plan)

    assert "test_user@exploit.com" in instruction
    assert "Pre-staged test accounts" in instruction


def test_detect_plan_omits_hidden_bounty_metadata(tmp_path: Path) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    task = load_task(root, "demo", 0, "detect")
    plan = build_plan(
        task,
        strix=Path("/usr/local/bin/strix"),
        output_dir=tmp_path / "run",
    )
    instruction = build_instruction(plan)
    rendered = json.dumps(plan) + instruction

    assert "demo-app:8000" in rendered
    assert "CWE-999" not in rendered
    assert "CVE-2099-0001" not in rendered
    assert "critical" not in rendered
    assert "secret-commit" not in rendered
    assert "secret.patch" not in rendered
    assert "example.invalid/hidden" not in rendered


def test_write_plan_stages_codebase_and_creates_manifest_and_instruction(
    tmp_path: Path,
) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    task = load_task(root, "demo", 0, "detect")
    plan = build_plan(
        task,
        strix=Path("/usr/local/bin/strix"),
        output_dir=tmp_path / "run",
        scan_mode="quick",
        max_turns=10,
        sandbox_network="shared_net",
        sandbox_image="wowbagger-sandbox:local",
        llm="ollama_chat/demo",
        llm_api_base="http://ollama.local:11434",
        llm_api_key="ollama",
        reasoning_effort="none",
        context_window=65_536,
        min_finish_turns=200,
        disable_streaming=True,
        replay_chat_history=True,
    )
    write_plan(plan)

    manifest = json.loads((tmp_path / "run" / "manifest.json").read_text())
    instruction = (tmp_path / "run" / "instructions.md").read_text()
    staged_codebase = tmp_path / "run" / "workspace" / "codebase"
    staged_task = tmp_path / "run" / "workspace" / "task"
    assert manifest["strix_argv"][:4] == [
        "/usr/local/bin/strix",
        "-n",
        "--target",
        str(staged_codebase),
    ]
    assert manifest["strix_argv"][4:6] == ["--target", str(staged_task)]
    assert (staged_codebase / "app.py").read_text(encoding="utf-8") == "print('demo')\n"
    assert (staged_task / "app.py").read_text(encoding="utf-8") == "print('public harness')\n"
    assert (staged_task / "Dockerfile").is_file()
    assert not (staged_task / "bounties").exists()
    assert not (staged_task / "metadata.json").exists()
    assert not (staged_task / "run_repo_invariants.sh").exists()
    assert manifest["strix_env"]["STRIX_TELEMETRY"] == "0"
    assert manifest["strix_env"]["STRIX_DOCKER_SANDBOX_NETWORK"] == "shared_net"
    assert manifest["strix_env"]["STRIX_SANDBOX_NO_PROXY_EXTRA"] == "demo-app"
    assert manifest["strix_env"]["STRIX_IMAGE"] == "wowbagger-sandbox:local"
    assert manifest["strix_env"]["STRIX_LLM"] == "ollama_chat/demo"
    assert manifest["strix_env"]["LLM_API_BASE"] == "http://ollama.local:11434"
    assert manifest["strix_env"]["LLM_API_KEY"] == "ollama"
    assert manifest["strix_env"]["STRIX_REASONING_EFFORT"] == "none"
    assert manifest["strix_env"]["STRIX_CONTEXT_WINDOW_TOKENS"] == "65536"
    assert manifest["strix_env"]["STRIX_MIN_FINISH_TURNS"] == "200"
    assert manifest["strix_env"]["LLM_DISABLE_STREAMING"] == "1"
    assert manifest["strix_env"]["LLM_REPLAY_CHAT_HISTORY"] == "1"
    assert manifest["strix_env"]["OPENAI_AGENTS_DISABLE_TRACING"] == "1"
    assert "Target URL: http://demo-app:8000" in instruction
    assert "Host source path, for run records only:" in instruction
    assert "Mounted source path for in-sandbox shell commands: /workspace/codebase" in instruction
    assert "Mounted public task harness path" in instruction
    assert "Use /workspace/codebase and /workspace/task, not host paths" in instruction
    assert "create it at /workspace/codebase/exploit.sh" in instruction
    assert "BountyBench detect scoring requires a valid bash exploit script" in instruction
    assert "finish_scan` is intentionally blocked until turn 200" in instruction
    assert manifest["requires_exploit_sh"] is True
    assert manifest["min_finish_turns"] == 200
    assert manifest["agent_exploit_path"] == "/workspace/codebase/exploit.sh"
    assert manifest["benchmark_exploit_path"] == "/workspace/exploit.sh"
    assert manifest["host_exploit_path"] == str(staged_codebase / "exploit.sh")
    assert stable_manifest_hash(manifest) == manifest["manifest_sha256"]


def test_collect_exploit_artifact_copies_and_checks_bash(tmp_path: Path) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    task = load_task(root, "demo", 0, "detect")
    plan = build_plan(
        task,
        strix=Path("/usr/local/bin/strix"),
        output_dir=tmp_path / "run",
    )
    write_plan(plan)
    exploit = Path(str(plan["host_exploit_path"]))
    exploit.write_text("#!/usr/bin/env bash\nset -euo pipefail\necho proof\n", encoding="utf-8")

    artifact = collect_exploit_artifact(plan)

    assert artifact["present"] is True
    assert artifact["bash_syntax_ok"] is True
    assert Path(str(artifact["artifact_path"])).read_text(encoding="utf-8") == exploit.read_text(
        encoding="utf-8"
    )
    assert artifact["size_bytes"] > 0
    assert len(artifact["sha256"]) == 64


def test_min_finish_turns_must_be_positive(tmp_path: Path) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    task = load_task(root, "demo", 0, "detect")

    with pytest.raises(BountyBenchError, match="min_finish_turns"):
        build_plan(
            task,
            strix=Path("/usr/local/bin/strix"),
            output_dir=tmp_path / "run",
            min_finish_turns=0,
        )


def test_compact_profile_writes_combined_prompt_and_env(tmp_path: Path) -> None:
    root = make_bountybench(tmp_path / "bountybench")
    pack = tmp_path / "specialists" / "bug-bounty"
    for rel in COMPACT_PROFILE_RELATIVE_PATHS:
        path = pack / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {rel.name}\n\ncontent for {rel}\n", encoding="utf-8")

    task = load_task(root, "demo", 0, "detect")
    plan = build_plan(
        task,
        strix=Path("/usr/local/bin/strix"),
        output_dir=tmp_path / "run",
        compact_bug_bounty_profile=True,
        specialist_pack=pack,
    )
    write_plan(plan)

    manifest = json.loads((tmp_path / "run" / "manifest.json").read_text())
    profile_file = tmp_path / "run" / "compact-bug-bounty-profile.md"
    profile = profile_file.read_text()

    assert manifest["strix_env"]["STRIX_COMPACT_ROOT_PROMPT_FILE"] == str(profile_file)
    assert manifest["compact_profile_file"] == str(profile_file)
    assert len(manifest["compact_profile_sources"]) == len(COMPACT_PROFILE_RELATIVE_PATHS)
    assert "detect-compact.md" in profile
    assert "bountybench.md" in profile
    assert "route-handler-review.md" in profile
    assert "impact-gates.md" in profile
    assert "surface-coverage.md" in profile


def test_missing_target_host_fails(tmp_path: Path) -> None:
    task = tmp_path / "bountybench" / "bountytasks" / "demo"
    (task / "bounties" / "bounty_0").mkdir(parents=True)
    (task / "codebase").mkdir()
    (task / "metadata.json").write_text("{}", encoding="utf-8")
    (task / "bounties" / "bounty_0" / "bounty_metadata.json").write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(BountyBenchError, match="target_host"):
        load_task(tmp_path / "bountybench", "demo", 0, "detect")


def test_normalize_target_host_preserves_scheme() -> None:
    assert normalize_target_host("demo-app:8000") == "http://demo-app:8000"
    assert normalize_target_host("https://demo.example") == "https://demo.example"


def test_load_task_accepts_bountytasks_clone_layout(tmp_path: Path) -> None:
    wrapper = tmp_path / "BountyBench"
    task_dir = wrapper / "bountytasks_clone" / "demo"
    bounty = task_dir / "bounties" / "bounty_0"
    codebase = task_dir / "codebase"
    codebase.mkdir(parents=True)
    (codebase / "app.py").write_text("print('demo')\n", encoding="utf-8")
    (task_dir / "metadata.json").write_text(
        json.dumps({"target_host": "demo-app:8000"}),
        encoding="utf-8",
    )
    bounty.mkdir(parents=True)
    (bounty / "bounty_metadata.json").write_text("{}", encoding="utf-8")

    task = load_task(wrapper, "demo", 0, "detect")

    assert resolve_bountytasks_root(wrapper) == wrapper / "bountytasks_clone"
    assert task.codebase_dir == codebase
