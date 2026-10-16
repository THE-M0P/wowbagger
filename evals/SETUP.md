# wowbagger setup guide

Everything you need to go from zero to a running engagement.

---

## Prerequisites

- **Docker** — the agent runs inside a Kali-based sandbox container
- **Python 3.12+** — for the `engage` CLI and strix runtime
- **Go 1.24+** — for the strix TUI sidecar (`go version` to check; install from [go.dev](https://go.dev/dl/))
- **An LLM** — Anthropic API, OpenAI API, or a local model via a compatible server

---

## 1. Clone wowbagger

```bash
git clone https://github.com/THE-M0P/wowbagger ~/src/wowbagger
```

---

## 2. Install strix

The repo ships a patched strix runtime under `runtime/`. Install it from there — **do not** use `pip install strix-agent` from PyPI, that version is missing features engage depends on.

```bash
pip install -e ~/src/wowbagger/runtime/
```

Verify it's on your PATH:
```bash
strix --version
```

If it prints a version you're good. If not, note the full path to the binary — you'll need it for config.

```bash
git clone https://github.com/THE-M0P/wowbagger ~/src/wowbagger
```

---

## 3. Get the sandbox image

Pull the pre-built image from GHCR (recommended — no build time):
```bash
docker pull ghcr.io/the-m0p/wowbagger:latest
```

Or build locally (~30 min on first build, layers cache on rebuild):
```bash
cd ~/src/wowbagger
docker build -t wowbagger-sandbox:local -f containers/Dockerfile .
```

If you pulled from GHCR, your `sandbox_image` in config will be `ghcr.io/the-m0p/wowbagger:latest`.
If you built locally, use `wowbagger-sandbox:local`.

---

## 4. Install the engage CLI

```bash
pip install -e ~/src/wowbagger/evals/
```

Verify:
```bash
engage --help
```

---

## 5. Write your config

```bash
mkdir -p ~/.config/wowbagger-evals
cp ~/src/wowbagger/evals/config.example.toml ~/.config/wowbagger-evals/config.toml
```

Open `~/.config/wowbagger-evals/config.toml` and fill in your values. Here's what each field means and what to put there:

---

### `strix`

Path to the strix binary. Skip this if `strix` is already in your PATH.

```toml
strix = "~/.local/bin/strix"
# or wherever pip installed it:
strix = "~/src/wowbagger/runtime/.venv/bin/strix"
```

---

### `llm`

The model to use for the agent. Uses [LiteLLM model IDs](https://docs.litellm.ai/docs/providers).

**Anthropic (Claude):**
```toml
llm = "anthropic/claude-sonnet-5-5"
llm = "anthropic/claude-haiku-4-5-20251001"
```
> Always use the `anthropic/` prefix. A bare `claude-*` name routes through the OpenAI client and will fail.

**OpenAI:**
```toml
llm = "openai/gpt-4o"
```

**Local model (llama.cpp / llama-server):**
```toml
llm = "openai/your-model-name-here"
# The name must match exactly what your server loaded — check with:
# curl http://localhost:11434/v1/models
```

---

### `llm_api_base`

The base URL for LLM API calls. **Leave this out for Anthropic or OpenAI** — they use their default endpoints. Set it only for local models or a proxy.

**llama.cpp / llama-server running locally:**
```toml
llm_api_base = "http://localhost:11436/v1"
```

**Ollama:**
```toml
llm_api_base = "http://localhost:11434/v1"
```

**LiteLLM proxy:**
```toml
llm_api_base = "http://localhost:4000"
```

---

### `llm_api_key`

Your API key.

**Anthropic:**
```toml
llm_api_key = "sk-ant-..."
```
Or set `ANTHROPIC_API_KEY` in your shell — LiteLLM picks it up automatically, in which case you can omit this line entirely.

**OpenAI:**
```toml
llm_api_key = "sk-..."
```
Or set `OPENAI_API_KEY`.

**Local model (no auth required):**
```toml
llm_api_key = "local"
```
Any non-empty string works — local servers ignore it.

---

### `context_window`

The model's context size in tokens. Must match your model — if you set this too high the agent will think it has more room than it does and get cut off.

| Model | Tokens |
|-------|--------|
| Claude Sonnet 4/5, Haiku 4 | `200000` |
| GPT-4o | `128000` |
| Qwen3 8B (llama-server) | `131072` |
| Qwen3 8B (llama-server, limited) | `110080` |
| Mistral 7B | `32768` |

When in doubt, check the model card. Setting it slightly lower than the actual limit is safe.

---

### `disable_streaming`

Set to `true` if your LLM provider doesn't support streaming, or if you're seeing garbled output. Most local llama-server setups need this.

```toml
disable_streaming = true   # local models
disable_streaming = false  # Anthropic/OpenAI (default)
```

---

### `sandbox_image`

The Docker image to use for every run. Must match what you pulled/built in step 3.

```toml
sandbox_image = "ghcr.io/the-m0p/wowbagger:latest"   # pulled from GHCR
sandbox_image = "wowbagger-sandbox:local"              # built locally
```

---

### `specialist_pack`

Path to the specialist pack for `engage run --mode whitebox`. The pack is a directory of Markdown profiles that tell the agent what to test and how.

```toml
specialist_pack = "~/src/wowbagger/specialists/multi-specialist"
```

The repo includes three packs:

| Pack | Path | Use with |
|------|------|----------|
| `multi-specialist` | `specialists/multi-specialist/` | `engage orchestrate` — 9 domain specialists, coordinator-driven |
| `bug-bounty` | `specialists/bug-bounty/` | `engage run --mode whitebox` — single generalist explorer+auditor |
| `bug-bounty-target` | `specialists/bug-bounty-target/` | `engage run --mode target` — black-box, H1/CTF/lab |

For most engagements start with `multi-specialist` and use `engage orchestrate`.

---

### `target_specialist_pack`

Pack for `engage run --mode target` (black-box). Defaults to `bug-bounty-target` if installed from the repo.

```toml
target_specialist_pack = "~/src/wowbagger/specialists/bug-bounty-target"
```

---

### `explore_turns` / `audit_turns`

Hard turn ceiling per run phase. The agent is force-stopped if it reaches this many LLM turns. Context pressure usually causes an earlier wrap-up — these are backstops.

```toml
explore_turns = 150   # generous for complex targets
audit_turns   = 80
```

Defaults (if unset): `explore_turns = 50`, `audit_turns = 40`. Raise them for large targets; lower them to save API cost on quick checks.

---

### `wrap_up_at_pressure`

Context pressure fraction at which the agent gets an urgent "write your findings now" directive. Tune this to your model's context window — set it higher to squeeze in more exploration, lower to leave more room for the write-up.

```toml
wrap_up_at_pressure = 0.85   # inject directive at 85% context fill
```

A good starting value is `0.85`. If you're seeing truncated reports, lower it to `0.75`.

---

## 6. Verify everything works

```bash
engage smoke
```

This runs all sandbox tools against a loopback target inside the container. It should exit 0 and write a report to `~/wowbagger-runs/smoke/smoke-<timestamp>/smoke-master-report.md`.

If it fails, check:
- Docker is running (`docker ps` works)
- The sandbox image exists (`docker images | grep wowbagger`)
- strix is reachable (`strix --version`)
- Your LLM responds (`engage smoke --llm anthropic/claude-haiku-4-5-20251001` to override the config for a quick test)

---

## 7. Run your first engagement

### Whitebox — you have the source code and a running container

```bash
# 1. Write a brief instructions.md for the target
mkdir -p ~/engagements/myapp
cat > ~/engagements/myapp/instructions.md << 'EOF'
# My App — Security Assessment

## Target
- URL: http://localhost:3000
- Source: ~/src/myapp
- Stack: Node.js / PostgreSQL

## Scope
All HTTP endpoints, source code, and running services.

## Test accounts
- Admin: admin@example.com / password123
- User:  user@example.com  / password123
EOF

# 2. Start the target (however it starts)
docker compose -f ~/src/myapp/docker-compose.yml up -d

# 3. Run
engage orchestrate \
    --mode whitebox \
    --codebase ~/src/myapp \
    --target http://localhost:3000 \
    --instructions ~/engagements/myapp/instructions.md \
    --engagement ~/engagements/myapp/chain-001
```

### Black-box — live URL only

```bash
engage run --mode target \
    --target https://app.example.com \
    --instructions ~/engagements/myapp/instructions.md \
    --engagement ~/engagements/myapp/chain-001
```

### Watch it run

In a second terminal:
```bash
engage watch ~/engagements/myapp/chain-001
```

---

## All flags

Every flag for every command is documented in the CLI itself:

```bash
engage --help
engage run --help
engage orchestrate --help
engage smoke --help
engage watch --help
```

The flags that aren't self-explanatory (`--inject-header`, `--block-host`, `--scan-mode`, `--sandbox-network`, `--coordinator-llm`, `--start-with`) are explained in the examples sections of the README.

---

## Minimal working config

If you want the shortest possible config that works, here it is for Anthropic:

```toml
llm           = "anthropic/claude-sonnet-5-5"
sandbox_image = "ghcr.io/the-m0p/wowbagger:latest"
specialist_pack = "~/src/wowbagger/specialists/multi-specialist"
```

And for a local llama-server at `localhost:11436`:

```toml
llm               = "openai/your-model-name"
llm_api_base      = "http://localhost:11436/v1"
llm_api_key       = "local"
context_window    = 131072
disable_streaming = true
sandbox_image     = "ghcr.io/the-m0p/wowbagger:latest"
specialist_pack   = "~/src/wowbagger/specialists/multi-specialist"
```

---

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `strix: command not found` | strix not on PATH | Set `strix = "/full/path/to/strix"` in config |
| `No sandbox image` | Docker image not pulled/built | `docker pull ghcr.io/the-m0p/wowbagger:latest` |
| `LLM returned error 401` | Wrong or missing API key | Set `llm_api_key` in config or export `ANTHROPIC_API_KEY` |
| `LLM returned error 404` | Wrong model ID | Check the `anthropic/` prefix for Claude; verify model name |
| Garbled / empty LLM output | Streaming not supported by provider | Set `disable_streaming = true` |
| Agent hits turn limit with no report | `explore_turns` too low, context filled | Raise `explore_turns`, lower `wrap_up_at_pressure` |
| `context_window` mismatch warning | Config doesn't match model | Update `context_window` to match the model's actual limit |
