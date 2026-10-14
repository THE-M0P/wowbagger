# Setup Guide

Get from zero to running `engage smoke` in about an hour.

## Prerequisites

- Docker installed and running
- Python 3.12+
- An LLM API key (Anthropic, OpenAI, or a local model via `LLM_API_BASE`)

## 1. Clone the repo

```bash
git clone https://github.com/THE-M0P/wowbagger ~/src/wowbagger
```

The repo contains the Dockerfile (`containers/`), the evals package (`evals/`),
and all specialist packs (`specialists/`).

## 2. Get the sandbox image

**Option A — pull from registry (fastest):**
```bash
docker pull ghcr.io/THE-M0P/wowbagger:latest
```

**Option B — build locally:**
```bash
cd ~/src/wowbagger
docker build -t wowbagger-sandbox:local -f containers/Dockerfile .
# Takes ~30 min on first build; layers cache on rebuild
```

## 3. Install wowbagger-evals

```bash
pip install -e ~/src/wowbagger/evals/
engage --help   # should print usage
```

## 4. Configure

```bash
mkdir -p ~/.config/wowbagger-evals
cp ~/src/wowbagger/evals/config.example.toml ~/.config/wowbagger-evals/config.toml
```

Edit `~/.config/wowbagger-evals/config.toml` — fill in at minimum:

```toml
specialist_pack = "~/src/wowbagger/specialists/multi-specialist"
sandbox_image   = "wowbagger-sandbox:local"   # or ghcr.io/THE-M0P/wowbagger:latest
```

If `strix` is in your `PATH`, you can skip the `strix` key entirely — it auto-detects.

## 5. Smoke test

Verify the image has all tools working:

```bash
# With Anthropic API key — use the anthropic/ prefix so it routes through LiteLLM:
LLM_API_KEY=<your-key> engage smoke \
  --llm anthropic/claude-haiku-4-5-20251001 \
  --sandbox-image wowbagger-sandbox:local

# Or with any OpenAI-compatible local model:
engage smoke \
  --llm openai/<model-name> \
  --llm-api-base http://<host>:<port>/v1 \
  --llm-api-key local \
  --context-window <token-count> \
  --disable-streaming \
  --sandbox-image wowbagger-sandbox:local
```

> **Claude model prefix**: always pass `anthropic/<model-id>` (routes through LiteLLM).
> A bare `claude-*` name routes to the OpenAI backend and fails with a
> `cache_control_injection_points` TypeError.

Exits 0 if everything passes. Look for `PASS — all tools verified` in the output.
Report from the run lands in `~/wowbagger-runs/smoke/smoke-<timestamp>/smoke-report.md`.

Note: smoke auto-selects the `multi-specialist` pack (which contains `smoke-test.md`).
You can override with `--specialist-pack <path>`.

## Running your first engagement

**Whitebox (BountyBench):**
```bash
engage run --mode whitebox \
  --project lunary \
  --engagement ~/engagements/lunary/chain-001 \
  --rounds 3 --stop-on-dry-runs 2 \
  --llm anthropic/claude-sonnet-5-5
```

**Black-box target (H1, CTF, lab):**
```bash
# Copy and fill in the instructions template first:
cp ~/src/wowbagger/specialists/bug-bounty-target/templates/instructions.md \
   ~/programs/example/instructions.md

engage run --mode target \
  --target https://app.example.com \
  --instructions ~/programs/example/instructions.md \
  --engagement ~/engagements/example/chain-001 \
  --rounds 5 \
  --llm anthropic/claude-sonnet-5-5
```

**Multi-specialist orchestration:**
```bash
engage orchestrate --mode whitebox \
  --project agentscope \
  --engagement ~/engagements/agentscope/chain-001 \
  --rounds-per-specialist 5 \
  --llm anthropic/claude-sonnet-5-5
```

**Watch a running engagement in a second terminal:**
```bash
engage watch ~/engagements/agentscope/chain-001
```

Shows context pressure, coordinator specialist picks, live findings count, and recent tool activity. Updates every 2 seconds, flicker-free. Press Ctrl-C to exit.

### Context pressure and turn limits

Each specialist has two independent stop conditions:

- **`--max-turns N`** (default 120): hard turn ceiling with graduated warnings at 70 %, 85 %, 95 %.
- **`--wrap-up-at-pressure FRACTION`** (default 0.85): once context usage crosses this threshold, the agent is told to stop exploring and write its report. It sees the live pressure percentage and a 95 % deadline on every remaining turn.

On runs with many tools or verbose output the context fills long before `max-turns` is reached. `--wrap-up-at-pressure` is what ensures the agent still produces a report in those cases. Pass `--context-window` so strix knows the actual window size of your model.


## Environment variables (alternative to config.toml)

| Variable | What it sets |
|----------|-------------|
| `STRIX_BIN` | Path to strix binary |
| `ENGAGE_SPECIALIST_PACK` | CVE/whitebox specialist pack path |
| `ENGAGE_TARGET_SPECIALIST_PACK` | Target specialist pack path |
| `ENGAGE_SANDBOX_IMAGE` | Docker image name |
| `LLM_API_KEY` | API key for LLM |
| `LLM_API_BASE` | API base URL (for local models or proxy) |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `strix: command not found` | `pip install strix-agent` or set `STRIX_BIN` |
| `smoke-report.md not found` | Image may have failed to start — check Docker is running and `--sandbox-image` is correct |
| `FAIL` lines in smoke report | Tool-specific fix; check the report for the failing tool name |
| `explore dir already exists` | Delete `run-00N-explore/` from the engagement dir and rerun |
| LLM connection failed | Check `LLM_API_KEY` is set; for local models check `LLM_API_BASE` points to a running server |
