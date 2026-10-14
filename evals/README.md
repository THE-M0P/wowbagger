# wowbagger-evals

Automated multi-specialist security testing pipeline. Runs explore→audit chains against any
target — whitebox (BountyBench / source+container), live H1 programs, CTF boxes, or lab VMs —
dispatching domain specialists driven by an LLM coordinator.

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/THE-M0P/wowbagger ~/src/wowbagger
```
Contains the Dockerfile, this evals package, and all specialist packs in one place.

**2. Get the sandbox image**

Pull from GHCR (fastest):
```bash
docker pull ghcr.io/THE-M0P/wowbagger:latest
```

Or build locally (takes ~30 min on first build, layers cache on rebuild):
```bash
cd ~/src/wowbagger && docker build -t wowbagger-sandbox:local -f containers/Dockerfile .
```

**3. Install this package**
```bash
pip install -e ~/src/wowbagger/evals/
```
This installs the `engage` CLI and its dependencies (`rich`, `textual`, `strix-agent`).

**4. Configure**
```bash
mkdir -p ~/.config/wowbagger-evals
cp ~/src/wowbagger/evals/config.example.toml ~/.config/wowbagger-evals/config.toml
# Edit: set specialist_pack, sandbox_image, and your LLM at minimum
```

## Commands

### Verify the image works
```bash
engage smoke
```
Runs all tools against a loopback target inside the container. Exits 0 if everything passes.
Report lands in `~/wowbagger-runs/smoke/smoke-<timestamp>/smoke-master-report.md`.
With `--max-smoke-loops N` (default 5) it loops if the context runs out mid-test, picking up where it left off.

### Whitebox — source code + running container
```bash
engage run --mode whitebox \
    --codebase ~/src/myapp \
    --target http://localhost:3000 \
    --instructions ~/engagements/myapp/instructions.md \
    --engagement ~/wowbagger-runs/engagements/myapp/chain-001 \
    --rounds 5 --stop-on-dry-runs 2 \
    --llm anthropic/claude-sonnet-5-5
```

### Multi-specialist orchestration
```bash
engage orchestrate --mode whitebox \
    --codebase ~/src/myapp \
    --target http://localhost:3000 \
    --instructions ~/engagements/myapp/instructions.md \
    --engagement ~/wowbagger-runs/engagements/myapp/chain-001 \
    --rounds-per-specialist 5 \
    --llm anthropic/claude-sonnet-5-5
```
Runs engagement-explore → LLM coordinator picks next specialist → repeat until exhausted.

### Black-box target (H1, CTF, lab)
```bash
engage run --mode target \
    --target https://app.example.com \
    --instructions ~/programs/example/instructions.md \
    --engagement ~/wowbagger-runs/engagements/example/chain-001 \
    --llm anthropic/claude-sonnet-5-5
```

### Watch a running engagement
```bash
engage watch ~/wowbagger-runs/engagements/example/chain-001
```
Textual TUI: status panel (turn, context pressure, findings) + scrollable full-history activity log.
Keybindings: `q` quit · `f`/`G` follow tail · trackpad or ↑↓/Page Up/Down to scroll back.

## Configuration

All paths can be set in `~/.config/wowbagger-evals/config.toml` (see `config.example.toml`)
or via environment variables:

| Env var | Config key | What it sets |
|---------|------------|--------------|
| `STRIX_BIN` | `strix` | Path to strix binary (auto-detected if strix is in PATH) |
| `ENGAGE_SPECIALIST_PACK` | `specialist_pack` | Whitebox specialist profiles |
| `ENGAGE_TARGET_SPECIALIST_PACK` | `target_specialist_pack` | Target specialist profiles (also accepts legacy `ENGAGE_H1_SPECIALIST_PACK`) |
| `ENGAGE_SANDBOX_IMAGE` | `sandbox_image` | Docker image for every run |
| `LLM_API_KEY` | — | API key (Anthropic or proxy) |
| `LLM_API_BASE` | — | API base URL (for local models / liteLLM proxy) |

## Specialist packs

A specialist pack is a directory with:
```
profiles/
  engagement-explore.md   ← generic explorer profile
  audit-verify.md         ← generic auditor profile
  auth-specialist.md      ← domain specialist profiles
  audit-auth.md           ← matching auditor profiles
  ...
specialists.json          ← maps specialist keys → profile pairs + descriptions
templates/
  master-report.md
  run-additions.md
```

`specialists.json` drives `engage orchestrate` — the coordinator reads it to decide
which specialist to run next.

## Repo structure

```
wowbagger/
  containers/            ← Dockerfile + parser scripts (nmap-parse, etc.)
  evals/                 ← this package
    src/wowbagger_evals/
      config.py          ← central path resolution (env > config file > default)
      engage.py          ← engage run / orchestrate / smoke
    config.example.toml
    SETUP.md
  specialists/           ← specialist packs
    bug-bounty/          ← whitebox mode (source + container)
    multi-specialist/    ← orchestrate + smoke (9 explorers, 9 auditors)
    bug-bounty-target/   ← target mode (H1, CTF, lab)
  .github/
    workflows/
      docker-image.yml   ← builds and pushes image to GHCR
```
