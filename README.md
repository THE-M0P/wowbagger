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

`--inject-header` adds a header to every proxied request via Caido.
`--block-host` null-routes a domain inside the sandbox so the agent can't reach it.

### Smoke test

Verify the sandbox image has all tools working before a real run:

```bash
engage smoke
```

---

## Specialist packs

| Pack | Use case | Profiles |
|------|----------|---------|
| [`specialists/bug-bounty-cve/`](specialists/bug-bounty-cve/) | Whitebox · orchestration · smoke test | 9 explorers + 9 auditors + smoke-test |
| [`specialists/bug-bounty-target/`](specialists/bug-bounty-target/) | Black-box live targets (H1, CTF, lab) | explorer + auditor |
| [`specialists/bug-bounty/`](specialists/bug-bounty/) | Simple whitebox single-specialist runs | explorer + auditor |

Each specialist pack is a directory of Markdown profiles. Profiles are the only thing the agent sees — swap them to change behavior without touching any code.

---

## Configuration

All settings live in `~/.config/wowbagger-evals/config.toml`. Copy `evals/config.example.toml` to start.

The LLM, API base, context window, and specialist pack paths can all be set there so you don't repeat them on every command:

```toml
llm             = "anthropic/claude-sonnet-5-5"
sandbox_image   = "ghcr.io/THE-M0P/wowbagger:latest"
specialist_pack = "~/src/wowbagger/specialists/bug-bounty-cve"
```

> **Note for Claude models:** always use the `anthropic/` prefix (e.g. `anthropic/claude-sonnet-5-5`).
> A bare `claude-*` name routes through the OpenAI client and fails.

Full config reference: [evals/README.md](evals/README.md)

---

## Repo layout

```
wowbagger/
  containers/      Kali-based Dockerfile + helper scripts (nmap-parse, ffuf-parse, …)
  evals/           engage CLI — run / orchestrate / smoke
  specialists/     specialist profile packs
  .github/
    workflows/
      docker-image.yml   builds and pushes to GHCR on containers/ changes
```

---

## License

MIT — see [LICENSE](LICENSE)
