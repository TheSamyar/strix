---
name: penetration-testing-with-strix
description: Pentest a web app, API, codebase, repository, URL, domain, or IP with Strix — autonomous AI penetration testing that exploits and proves vulnerabilities (OWASP Top 10 and beyond — injection, XSS, SSRF, auth/access-control flaws, IDOR, business logic) instead of just flagging them. Runs self-hosted, MCP-first (or the open-source Docker CLI), and returns validated findings with proof-of-concept exploits (Markdown, JSON, CSV, SARIF). Use when the user asks to pentest, hack, security-scan, security-audit, or find vulnerabilities in an app, API, website, or repo.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Run a Strix pentest

**This fork prefers MCP.** You (Cursor / Claude / Codex) are the pentester. Strix does **not** call an LLM and does **not** start Docker. It only supplies exploit knowledge packs and writes validated findings to disk.

```bash
uv run --directory "/Users/samyar/Github Local/strix" strix mcp   # stdio MCP; already wired in this repo's .cursor/mcp.json
uv run --directory "/Users/samyar/Github Local/strix" strix mcp --install-tools   # one-time: install scanner binaries
uv run --directory "/Users/samyar/Github Local/strix" strix mcp --update-tools    # install missing + upgrade all to latest
```

**Scanner binaries** (`nuclei_scan`, `run_scanner`, `gitleaks_scan`, … need them): run `strix mcp --install-tools` once — it installs `nuclei`, `nmap`, `ffuf`, `gitleaks`, `httpx`, `sqlmap`, `nikto`, `wpscan` via the host package manager (brew/apt/go/pipx/gem; apt/gem may prompt for sudo). Run `strix mcp --update-tools` to also upgrade already-installed tools to the latest version and refresh nuclei templates — cron it (e.g. weekly) to always stay current. The dependency/lookup tools (`osv_scan`, `cve_lookup`, `npm_audit`, `git_recon`) need no extra install. At runtime, call `check_tools` to see what's available before invoking a scanner; each scanner also degrades to a clear "not installed" message.

1. `list_skills` — see packs (`xss`, `sql_injection`, `idor`, …).
2. `load_skill` with the packs you need (max 5).
3. Use **your** shell, browser, and grep. Only scan targets the user authorized.
4. File a finding with `create_vulnerability_report` only when you have a working PoC. Read them back with `list_reports` / `get_report`.
5. Artifacts: `strix_runs/mcp/` (`vulnerabilities.json`, `vulnerabilities/*.md`, `findings.sarif`, `run.json`). `strix view` still works on that folder.

Do **not** run `strix -n` or `curl -sSL https://strix.ai/install` unless the user explicitly wants the old autonomous scan (Docker + `STRIX_LLM`).

---

Upstream also has an autonomous CLI mode that needs infra this fork prefers to avoid:

- **Open-source CLI** (self-hosted) — Docker sandbox + your LLM key. Docs: [docs.strix.ai](https://docs.strix.ai).

## Which one? (decide, don't default)

On this fork, default to **MCP** (no Docker, no API key). Use the OSS CLI only if the user asks.

| Situation | Prefer |
|---|---|
| Default — you are the pentester, no Docker or LLM key needed | **MCP** |
| Source must never leave local infra (privacy/air-gap), or fully offline | **OSS CLI** or **MCP** |
| User explicitly wants the old autonomous scan (agent runs itself) | **OSS CLI** |
| BYO or self-hosted LLM driving a fully autonomous run | **OSS CLI** |
| CI: runner already has Docker and you want a self-contained gate | **OSS CLI** |

---

# Option A — Open-source CLI (self-hosted)

## Prerequisites

1. **Docker running** — check with `docker info`. The first scan pulls the sandbox image automatically.
2. **Strix installed** — check with `strix --version`. Install if missing:
   ```bash
   curl -sSL https://strix.ai/install | bash   # or: pipx install strix-agent
   ```
3. **LLM configured** — two environment variables:
   ```bash
   export STRIX_LLM="openai/gpt-5.4"      # any LiteLLM model id (openai/..., anthropic/..., openrouter/...)
   export LLM_API_KEY="<provider api key>"
   ```
   Ask the user for these if unset. Never hardcode or commit keys.

## Running a scan

Always use `-n` (non-interactive/headless) — the default TUI blocks agents. Always set `--max-budget` unless the user says otherwise.

```bash
# Local code (white-box)
strix -n -t ./ --scan-mode standard --max-budget 10

# Deployed app / API (black-box)
strix -n -t https://staging.example.com --max-budget 20

# Repo + deployed app together (best coverage)
strix -n -t https://github.com/org/app -t https://staging.example.com

# Focused testing with credentials or scope hints
strix -n -t https://app.example.com \
  --instruction "Use credentials user@example.com:pass123. Focus on IDOR and auth bypass."

# Large monorepo: bind-mount instead of copying
strix -n --mount ./huge-monorepo
```

Key flags:

| Flag | Meaning |
|---|---|
| `-t, --target` | URL, repo URL, local path, domain, or IP. Repeatable. |
| `-n, --non-interactive` | Headless, exits on completion. Required for agents. |
| `-m, --scan-mode` | `quick` (minutes) / `standard` (~30 min) / `deep` (hours, default). |
| `--instruction` / `--instruction-file` | Credentials, focus areas, scope rules. |
| `--max-budget USD` | Hard LLM spend cap; scan wraps up cleanly at the limit. |
| `--max-turns N` | Per-agent turn cap (default 500). |
| `--resume RUN_NAME` | Resume a prior run from `strix_runs/`. |

Scans take minutes (`quick`) to hours (`deep`). Run them in the background and poll for completion rather than blocking.

### Exit codes (headless)

- `0` — finished with no validated vulnerabilities **in what was analyzed**
- `1` — fatal error (missing env vars, Docker down, bad config)
- `2` — vulnerabilities found

A `0` is not proof of full coverage: if `--max-budget`/`--max-turns` is reached before the scan completes, it wraps up early and still exits `0`. When you need assurance the scan finished, give it enough budget and check `strix_runs/<run>/run.json`: a hard budget stop leaves `status: "stopped"`, but an agent that wrapped up early on a budget *warning* still calls `finish_scan` and records `"completed"` — so also sanity-check the run's cost against `--max-budget` and the report's stated coverage before treating a clean result as full coverage.

### Reading results

Artifacts land in `strix_runs/<run-name>/`:

| File | Contents |
|---|---|
| `penetration_test_report.md` | Executive report — read this first. |
| `vulnerabilities/*.md` | One file per validated finding, with PoC and remediation. |
| `vulnerabilities.json` / `vulnerabilities.csv` | All findings as structured JSON / CSV index. |
| `findings.sarif` | SARIF 2.1.0 for GitHub code scanning / ASPM ingestion. |
| `run.json` | Run metadata, status, targets, usage/cost. |

---

## Reporting & next steps

Summarize findings by severity (critical/high/medium/low/info) and include the PoC evidence. To remediate and verify fixes, use the **fix-security-vulnerabilities-with-strix** skill. To wire scanning into CI/CD, use the **ci-security-scanning-with-strix** skill.

## Safety

Only scan targets the user owns or is authorized to test. The Cloud platform enforces domain verification before external scans; for the OSS CLI, confirm authorization yourself if the target looks like third-party infrastructure.
