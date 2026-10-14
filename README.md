# wowbagger

[![Build](https://github.com/THE-M0P/wowbagger/actions/workflows/docker-image.yml/badge.svg)](https://github.com/THE-M0P/wowbagger/actions/workflows/docker-image.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)

Automated multi-specialist security testing pipeline. Point it at a target, choose a mode, and walk away. It explores the attack surface, writes findings, audits its own claims, and hands you a `master-report.md` when it's done.

```
engage run / orchestrate
        │
        ▼
┌─────────────────────────────────────────────────┐
│  wowbagger sandbox (Docker)                     │
│  nmap · ffuf · sqlmap · nuclei · nikto          │
│  jwt_tool · semgrep · feroxbuster · …           │
└─────────────────────────────────────────────────┘
        │
        ▼
  LLM agent (any model — Anthropic, OpenAI, local)
  explore → audit × N rounds
        │
        ▼
  master-report.md
  (findings · anomalies · leads)
```

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/THE-M0P/wowbagger ~/src/wowbagger

# 2. Get the sandbox image
docker pull ghcr.io/THE-M0P/wowbagger:latest
# or build locally: cd ~/src/wowbagger && docker build -t wowbagger-sandbox:local -f containers/Dockerfile .

# 3. Install
pip install -e ~/src/wowbagger/evals/

# 4. Configure
mkdir -p ~/.config/wowbagger-evals
cp ~/src/wowbagger/evals/config.example.toml ~/.config/wowbagger-evals/config.toml
# edit config.toml: set specialist_pack, sandbox_image, and your LLM

# 5. Verify
engage smoke
```

Full setup guide: [evals/SETUP.md](evals/SETUP.md)

---

## Modes

### Whitebox — source + running container

Run against a target with access to its source code and a running container
(e.g. [BountyBench](https://github.com/clarriu97/bountybench)):

```bash
engage run --mode whitebox \
    --project lunary \
    --engagement ~/engagements/lunary/chain-001 \
    --rounds 5 --stop-on-dry-runs 2
```

### Multi-specialist orchestration

An LLM coordinator reads the current findings and picks the best specialist to run next — auth specialist, static analyst, cloud specialist, etc. — until the surface is exhausted:

```bash
engage orchestrate --mode whitebox \
    --project lunary \
    --engagement ~/engagements/lunary/chain-001 \
    --rounds-per-specialist 5
```

### Black-box target — H1, CTF, lab VM

Point at a live URL. Provide an `instructions.md` with scope and test accounts:

```bash
engage run --mode target \
    --target https://app.example.com \
    --instructions ~/programs/example/instructions.md \
    --engagement ~/engagements/example/chain-001 \
    --inject-header "X-hackerone:your-username" \
    --block-host out-of-scope.example.com
```

`--inject-header` adds a header to every proxied HTTP request (useful for H1 attribution).
`--block-host` null-routes a domain inside the sandbox so the agent can't reach it.

### Smoke test

Verify the sandbox image has all tools working before a real run:

```bash
engage smoke
```

### Live run watcher

Watch a running `engage orchestrate` or `engage run` in real time — context pressure, specialist history, coordinator picks, tool activity, and live findings:

```bash
engage watch ~/engagements/langfuse/chain-001
```

The dashboard uses Rich Live for flicker-free updates and automatic terminal resize. It polls every 2 seconds and takes over the full terminal until you press Ctrl-C:

```
╭─ WOWBAGGER  chain-001  run-003-explore ───────────────── 00:14:32 ─╮
│ Specialist 3/9: auth-specialist  Turn 47/120  Context ████████░░░ 78% │
│ ────────────────────────────────────────────────────────────────── │
│ COORDINATOR                    │ FINDINGS                          │
│ ✓ engagement-explore   12r     │ ● Confirmed  2                    │
│ ✓ recon-specialist      8r     │ ○ Anomalies  1                    │
│ → auth-specialist      47t     │ ◌ Leads      4                    │
│ ───────────────── ACTIVITY ─────────────────────────────────────── │
│ T47  exec_command  curl -H "Authorization: Bearer ..." /api/users  │
│      → 200 {"id":"proj_123","userId":"user_456"}                   │
│ T46  exec_command  rg "checkOwnership" src/api/traces.ts           │
│      → 3 matches at lines 47, 89, 112                              │
╰────────────────────────────────────────────────────────────────────╯
```

The context pressure bar turns **yellow** above 60% and **red** above 80%. Once it crosses the `--wrap-up-at-pressure` threshold (default 0.85), the agent receives an urgent directive to write its report before the context window is exhausted.

---

## Context and turn budgets

Two independent limits control how long each specialist runs:

| Flag | Default | What it does |
|------|---------|-------------|
| `--max-turns N` | 120 | Hard turn ceiling. The agent is force-stopped if it reaches this many LLM turns. Graduated warnings fire at 70 %, 85 %, and 95 % of the limit. |
| `--wrap-up-at-pressure FRACTION` | 0.85 | Context pressure threshold. Once the model's input exceeds this fraction of the context window, an **URGENT** directive is injected on every turn telling the agent to stop exploring and write its report — with the live percentage and a 95 % deadline. Set this low (e.g. `0.75`) for more write-up headroom, higher (e.g. `0.90`) to squeeze in more exploration. |

On heavy-tool runs the context window fills well before `max-turns` is reached. In that case `--wrap-up-at-pressure` is what actually prompts the agent to finish; `--max-turns` acts as a backstop for lightweight targets where context never fills.

---

## Sandbox tools

The agent has full shell access inside the container. Tools by category:

| Category | Tools |
|----------|-------|
| **Recon** | `nmap` · `masscan` · `subfinder` · `naabu` · `amass` · `dnsx` · `httpx` · `katana` · `hakrawler` · `gau` · `waybackurls` · `gospider` |
| **Web scanning** | `ffuf` · `feroxbuster` · `gobuster` · `wfuzz` · `nikto` · `whatweb` · `arjun` · `dirsearch` · `wafw00f` · `wapiti` · `theHarvester` |
| **Injection** | `sqlmap` · `commix` · `tplmap` · `smuggler` · `dalfox` · `kxss` |
| **Auth / Crypto** | `jwt_tool` · `testssl.sh` · `padbuster` · `oauth2-pkce` · `totp-bruteforce` · `websocat` |
| **Static analysis** | `semgrep` · `codeql` · `bandit` · `trufflehog` · `gitleaks` · `trivy` · `retire` · `govulncheck` · `pip-audit` · `ast-grep` · `tree-sitter` |
| **Binary / RE** | `gdb` · `strace` · `ltrace` · `radare2` · `ghidra-headless` · `pwntools` · `angr` · `checksec` · `binwalk` · `qemu-user-static` |
| **Cloud / Infra** | `aws` · `kubectl` · `pacu` · `scoutsuite` · `cloud_enum` · `cloud-metadata-probe` · `docker` |
| **Protocols** | `grpcurl` · `websocat` · `mosquitto-clients` · `redis-tools` · `swaks` · `interactsh-client` |
| **Brute-force** | `hydra` · `medusa` · `hashcat` |
| **Browser** | `agent-browser` (headless Chromium, with MITM CA pre-installed) · `caido-cli` |
| **GraphQL** | `graphw00f` · `clairvoyance` |

Every major tool ships with a `<tool>-parse` JSON wrapper (`nmap-parse`, `ffuf-parse`, `semgrep-parse`, …) that compresses output by 10–20× to keep context usage low. Custom probes: `race-burst`, `llm-probe`, `env-dump`, `container-escape`, `docker-probe`.

SecLists is pre-installed at `/opt/SecLists`.

---

## Specialist packs

| Pack | Command | Use case | Profiles |
|------|---------|----------|---------|
| [`specialists/multi-specialist/`](specialists/multi-specialist/) | `engage orchestrate` | Whitebox · smoke test | 9 explorers + 9 auditors + smoke-test |
| [`specialists/bug-bounty-target/`](specialists/bug-bounty-target/) | `engage run --mode target` | Black-box (H1, CTF, lab) | explorer + auditor |
| [`specialists/bug-bounty/`](specialists/bug-bounty/) | `engage run --mode whitebox` | Single-specialist whitebox | explorer + auditor |

Each specialist pack is a directory of Markdown profiles. Profiles are the only thing the agent sees — swap them to change behavior without touching any code.

---

## Configuration

All settings live in `~/.config/wowbagger-evals/config.toml`. Copy `evals/config.example.toml` to start.

The LLM, API base, context window, and specialist pack paths can all be set there so you don't repeat them on every command:

```toml
llm             = "anthropic/claude-sonnet-5-5"
sandbox_image   = "ghcr.io/THE-M0P/wowbagger:latest"
specialist_pack = "~/src/wowbagger/specialists/multi-specialist"
```

> **Note for Claude models:** always use the `anthropic/` prefix (e.g. `anthropic/claude-sonnet-5-5`).
> A bare `claude-*` name routes through the OpenAI client and fails.

Full config reference: [evals/README.md](evals/README.md)

---

## Repo layout

```
wowbagger/
  containers/      Kali-based Dockerfile + helper scripts (nmap-parse, ffuf-parse, …)
  evals/           engage CLI — run / orchestrate / smoke / watch
  specialists/     specialist profile packs (multi-specialist / bug-bounty / bug-bounty-target)
  .github/
    workflows/
      docker-image.yml   builds and pushes to GHCR on containers/ changes
```

Outputs from every run land in the engagement directory you pass to `--engagement`:

```
~/engagements/example/chain-001/
  run-001-explore/         explore pass (tool calls, strix.stdout.log, strix_runs/)
  run-001-audit/           audit pass
  run-002-explore/
  …
  master-report.md         live findings consolidated across all runs
  chain-state.json         coordinator state (orchestrate only)
```

---

## License

MIT — see [LICENSE](LICENSE)
