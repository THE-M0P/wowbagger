# BountyBench Adapter

The adapter runs Strix as an external detector against BountyBench targets while keeping answer material outside the agent workspace.

## Current Flow

1. Read project metadata from `bountytasks/<project>/metadata.json`.
2. Confirm `bountytasks/<project>/bounties/bounty_<n>/bounty_metadata.json` exists without copying its contents into the prompt.
3. Generate `instructions.md` with only the target URL, source path, and generic assessment instructions.
4. Generate `manifest.json` with reproducibility metadata and the exact Strix argv.
5. Run pre-run CVE enrichment: `docker exec <container> pip list` → OSV batch API → individual GHSA lookups → searchsploit per CVE → write `workspace/task/package-intel.json`.
6. Execute Strix with telemetry disabled.

## Package Intel Enrichment

Before the agent starts, the adapter queries the running target container for installed Python packages, cross-references them with the OSV API, and writes `workspace/task/package-intel.json` to the task workspace.

The file lists every installed package with known vulnerabilities. Each vulnerable package entry includes:
- `cve` — the canonical CVE ID (from the GHSA record's aliases)
- `summary` — human-readable description (e.g. "python-multipart vulnerable to Content-Type Header ReDoS")
- `advisory_url` — direct link to the GHSA advisory
- `fixed_in` — version that patches the vuln
- `searchsploit` — any matching Exploit-DB PoC entries (if searchsploit is in the sandbox image)

Entries are sorted: packages with a real CVE ID and non-empty summary come first. Redundant PYSEC alias entries (whose ID already appears as an alias inside a resolved GHSA record) are suppressed — the canonical GHSA entry captures the same vuln with full detail.

OSV queries run on the host (not in the sandbox) before Strix starts. Failures go into `errors[]` and never abort the run.

## Adapter Contract

The adapter must not place CVE, CWE, severity, bounty links, vulnerable commits, patch mappings, exploit files, verify files, or writeups into Strix prompts or workspaces. `package-intel.json` is allowed because it is derived from runtime package inspection — it confirms what is installed, not what the answer is.

## Limitations

- Only detect mode is implemented.
- The target lifecycle is external: start the BountyBench Docker target before running the adapter.
- Codebase submodules must be initialized before the source target will be useful.
- The Strix sandbox must be able to resolve BountyBench service names such as `fastapi-app` on `shared_net`.
- `searchsploit` requires the `exploitdb` apt package in the sandbox image.

## Sandbox Image

The sandbox image is built from `containers/Dockerfile`. Build or pull it per the setup guide:

```bash
# Pull from registry
docker pull ghcr.io/THE-M0P/wowbagger:latest

# Or build locally
cd ~/src/wowbagger
docker build -t wowbagger-sandbox:local -f containers/Dockerfile .
```

## Launch Pattern

Eval runs require Docker group access. Use `engage run` (the current CLI):

```bash
engage run --mode whitebox \
  --project fastapi --bounty 0 \
  --engagement ~/engagements/fastapi/chain-001 \
  --rounds 5 --stop-on-dry-runs 2 \
  --llm anthropic/claude-sonnet-5-5
```

For local models (requires `LLM_API_BASE` pointing to a running llama-server or compatible endpoint):

```bash
engage run --mode whitebox \
  --project fastapi --bounty 0 \
  --engagement ~/engagements/fastapi/chain-001 \
  --rounds 5 \
  --llm openai/<model-name> \
  --llm-api-base http://localhost:11434/v1 \
  --llm-api-key local \
  --disable-streaming
```

See [SETUP.md](../SETUP.md) for full setup instructions.
