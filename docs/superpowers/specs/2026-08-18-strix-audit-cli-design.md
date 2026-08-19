# `strix audit` — coding-agent workers

Date: 2026-08-18

Headless audit CLI. One Python orchestrator hires Claude Code, Cursor Agent, or Codex as subprocess workers. No Docker. No `STRIX_LLM`. Findings persist through existing `strix mcp` into `strix_runs/<name>/`.

Independent audit (2026-08-18): **FIX-THEN-SHIP**. This spec incorporates that punch list.

## Goal

```bash
strix audit -t ./ --agent claude --scan-mode quick
strix audit -t https://app.example.com --agent cursor
strix audit -t ./openapi.yaml -t https://api.example.com --agent codex --scan-mode deep
```

User walks away. Exit codes match `strix -n`: `0` no vulns, `1` fatal, `2` vulns found.

## Non-goals (v1)

- Mixing agents in one run (every worker uses `--agent`)
- Manager LLM skip/add pass (playbook runs as-is; vendor JSON wrappers are unreliable)
- TUI / agent graph UI
- Docker sandbox / LiteLLM scan loop (`strix -n` unchanged)
- HTTP MCP
- Workers spawning their own sub-agents
- DIY `git worktree add` alongside vendor `-w` (double-nest)

## Command

New subcommand in `strix/interface/main.py`, **cloned from `mcp`/`auth`/`view`**: if `sys.argv[1] == "audit"`, `sys.exit(run_audit(sys.argv[2:])); return`. This runs **before** `parse_arguments()`. The scan parser has no `audit` subcommand; if dispatch is skipped, `strix audit -t ./` dies with `unrecognized arguments: audit` and then hits Docker preflight (`check_docker_installed` / `pull_docker_image`).

`run_audit` never calls `parse_arguments()`, `prepare_run()`, `validate_environment()`, `warm_up_llm()`, or `rewrite_localhost_targets(..., "host.docker.internal")`. Localhost URL targets must stay as `localhost` on the host.

Audit has its **own argparse**. Minimal target reuse: build a small `Namespace(target=…, target_list=…)` and call `build_targets_info(args)` only.

| Flag | Default | Meaning |
|---|---|---|
| `-t` / `--target` (repeatable) | required | Same as today (dir, URL, API spec, …) |
| `--target-list` | — | Same as today |
| `--agent` | first vendor binary on `PATH` (see Adapters) | Worker backend. Error if none found and flag omitted |
| `--scan-mode` / `-m` | `quick` | `quick` \| `standard` \| `deep` (scan CLI defaults to `deep`; audit does not reuse that parser) |
| `--run-name` | `generate_run_name()` (`{slug}_{2hex}`, same helper as scan) | Parent folder under `strix_runs/`. Reject names containing `..` |
| `--max-workers` | `3` | Parallel worker cap |
| `--timeout` | `3600` | Seconds per worker process |
| `--instruction` / `--instruction-file` | — | Appended to every worker prompt |

`--agent` values: `claude`, `cursor`, `codex`.

Default scan mode is `quick`: coding-agent workers are expensive.

## Architecture

```
strix audit
  → own argparse + build_targets_info
  → preflight (chosen vendor binary on PATH)
  → create strix_runs/<name>/  (parent run.json)
  → load playbook for scan-mode (no manager)
  → run jobs, ≤ --max-workers at a time
       each worker: vendor CLI (frozen argv) + private stdio MCP
       MCP cwd = ORIGINAL_CWD (the repo, not the worktree)
       artifacts: strix_runs/<name>/workers/<job>/
  → remint finding ids, write parent reports
  → exit 0/1/2
```

Docker scan path is untouched.

## Files

| Path | Role |
|---|---|
| `strix/interface/audit.py` | Argparse + `run_audit()` loop, logging, exit codes, worktree cleanup |
| `strix/audit.py` | Playbook, adapters (frozen argv), spawn, remint+merge |
| `strix/interface/main.py` | Dispatch `sys.argv[1] == "audit"` **before** `parse_arguments()` |
| `strix/interface/mcp_server.py` | Add `--no-seed` (skip coverage todos) and a short specialist instruction override when that flag is set |
| `tests/test_audit.py` | All unit tests below |
| `tests/test_mcp_server.py` | Cover `--no-seed` does not seed coverage todos |

No YAML playbook files. Jobs are a dict in `strix/audit.py`.

## Playbook

Each job: `id`, `title`, `skills` (1–3 existing pack names), `task` (specialist prompt). Pack names below exist under `strix/skills/`.

**quick (4):**

1. `recon` — skills: `asset_discovery`. Map surface; do not deep-exploit.
2. `auth` — skills: `authentication_jwt`, `csrf`.
3. `injection` — skills: `sql_injection`, `xss`, `rce`.
4. `access` — skills: `idor`, `broken_function_level_authorization`.

**standard (6):** quick plus

5. `ssrf_files` — skills: `ssrf`, `path_traversal_lfi_rfi`, `insecure_file_uploads`.
6. `secrets_deps` — skills: `information_disclosure`, `dependency_cve_scanning`.

**deep (8):** standard plus

7. `logic` — skills: `business_logic`, `race_conditions`.
8. `deser_ssti` — skills: `insecure_deserialization`, `ssti`.

Job `id` is the worker folder name (`[a-z0-9_]+`). v1 runs the full playbook for the scan mode. No skip/add manager.

## Workers

Prompt (fixed shape):

- You are specialist `<title>` for this Strix audit.
- Targets (original strings + classified type).
- `load_skill` each listed pack, then test. File **only validated** findings with `create_vulnerability_report`.
- Coverage todos are not seeded (`--no-seed`). Do not try to cover every vuln class.
- Do not spawn sub-agents / Task tools / extra CLI agents.
- When finished, print `AUDIT_JOB_DONE` and exit 0.

**MCP argv** (stdio, private per worker). Interpolating `RUN` into `-c` source is forbidden (quote-break + findings land in the worktree because `run_dir_for` uses `Path.cwd()`). Use an argv array and chdir to the original repo:

```
[sys.executable, "-c",
 "import os,sys; os.chdir(sys.argv[1]); from strix.interface.mcp_server import run_mcp; raise SystemExit(run_mcp(sys.argv[2:]))",
 ORIGINAL_CWD, "--run-name", f"{parent}/workers/{job}", "--no-seed"]
```

That nests as `strix_runs/<parent>/workers/<job>/` under `ORIGINAL_CWD`. MCP process cwd is `ORIGINAL_CWD`, not the vendor worktree.

`strix mcp --no-seed` skips `_seed_coverage_todos` and uses a short specialist `MCP_INSTRUCTIONS` (file findings, no full-pentest coverage checklist). Without this, every worker inherits “do not stop until the coverage checklist is done” and four concurrent full pentests.

No `python -m strix` (no `__main__.py`). No `--run-dir` in v1.

**Isolation**

- **Claude / Cursor:** vendor `-w` / `--workspace` only. Do **not** also `git worktree add`.
- **Codex:** `git worktree add --detach <path> HEAD` (plain `add … HEAD` fails when `main` is already checked out). Pass `-C <path>`. `remove --force` **only** the path this process added, after the worker is dead. Never touch `.claude/worktrees/` (unregistered copies; they do not appear in `git worktree list`).
- If the first local target is not git: workers on that dir run **sequentially** (ignore `--max-workers` for those jobs).
- URL/API-only runs: no worktree. Parallel is fine. Worker cwd = `ORIGINAL_CWD`.
- Mixed (`-t ./ -t https://…`): local dir uses vendor `-w` or Codex detach worktree; URL is in the prompt.

Workers must not commit, force-push, or change git config.

## Adapters

Frozen argv (probed 2026-08-18). Do not invent flags. Do not fall through to another vendor when `--agent X` is set and X is missing.

`--agent` omitted: first of `claude`, `cursor-agent` (or `agent`), `codex` on `PATH`. The `cursor` IDE binary is **not** an agent (`cursor --help` is the editor). Search list for `--agent cursor`: `cursor-agent`, then `agent`. Never `cursor`.

Adapters write vendor MCP config **into the worker/workspace dir** (not `~/.cursor` / `~/.codex`). Windows: pass argv arrays; no shell-string `-c`.

### Claude (`claude` → `/Users/samyar/.local/bin/claude` on this machine)

```
claude -p --dangerously-skip-permissions --strict-mcp-config --mcp-config <mcp.json> --output-format json
```

Optional: `-w <name>` for isolation (do not also DIY a worktree). `--permission-mode bypassPermissions` is the named equivalent of skip-permissions.

MCP file schema:

```json
{ "mcpServers": { "strix": { "type": "stdio", "command": "<sys.executable>", "args": ["-c", "<chdir-snippet>", "<ORIGINAL_CWD>", "--run-name", "<parent>/workers/<job>", "--no-seed"] } } }
```

`--strict-mcp-config` is required. Do not rely on `.mcp.json` (unapproved project servers stay pending).

### Cursor (`cursor-agent` or `agent`, same CLI)

```
cursor-agent -p --force --sandbox disabled --approve-mcps --trust --workspace <dir>
```

`--yolo` = `--force`. **No `--mcp-config` flag.** Write `<workspace>/.cursor/mcp.json` (same schema as this repo’s file). `--approve-mcps` is required or it prompts.

### Codex (`codex` → `/opt/homebrew/bin/codex` on this machine)

```
codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -C <dir> \
  -c 'mcp_servers.strix_audit.command="<sys.executable>"' \
  -c 'mcp_servers.strix_audit.args=["-c","<chdir-snippet>","<ORIGINAL_CWD>","--run-name","<parent>/workers/<job>","--no-seed"]' \
  -c 'mcp_servers.strix_audit.cwd="<ORIGINAL_CWD>"'
```

`--sandbox danger-full-access` is milder; the dangerously-bypass flag is the unattended one. Inject MCP via `codex exec -c` (highest precedence). Do not mutate `~/.codex/config.toml`. Project `.codex/config.toml` loads only if trusted — do not depend on it.

Unattended flags above are required. Without them the walk-away promise is false.

## Merge

Each MCP process allocates `vuln-{n:04d}` from `len(vulnerability_reports)+1`. Every worker’s first finding is `vuln-0001`. Deduping by id and keeping first **drops every later worker’s reports**. `write_vulnerabilities` rewrites `vulnerabilities/<id>.md` from the dict (`id`, `severity`, `timestamp` required for sort). Copying md is redundant and overwrites on collision.

After all workers finish (including failures):

1. Read each `strix_runs/<name>/workers/<job>/vulnerabilities.json` (skip missing/corrupt with a warning).
2. Concatenate report dicts (no id dedupe).
3. Remint `id` to `vuln-0001…N` in concat order.
4. `write_vulnerabilities(parent, reports, saved_vuln_ids=set())` then `write_sarif(parent, reports)` then `write_executive_report`. Executive body is a short Python-built summary: job statuses + finding titles/severities. No extra LLM call. SARIF rule ids prefer CWE/CVE, not finding id, so reminting is safe.
5. Parent `run.json`: `status` (`completed` / `error`), `agent`, `jobs` (id, exit, timed_out), finding count.

Filing-time fields (already enforced by MCP): `title, description, impact, target, technical_analysis, poc_description, poc_script_code, remediation_steps, evidence, assumptions`, plus verification/CVSS inside `_do_create`.

## Errors

| Case | Behavior |
|---|---|
| No `-t` | argparse error, exit 1 |
| `--agent` missing and no vendor on PATH | exit 1, print the three install hints |
| `--agent X` not on PATH | exit 1, one hint for X |
| Worker non-zero | log, mark job failed, continue |
| Worker timeout | kill process group, mark `timed_out`, continue |
| All workers fail and no findings | exit 1 |
| Any findings | exit 2 even if some jobs failed |
| No findings and at least one job exit 0 | exit 0 |

`strix -n` today: implicit 0 if `main()` returns; 1 on Docker/LLM/argparse/signal; 2 only if non-interactive and `report_state.vulnerability_reports` is non-empty (`main.py` ~501–504). Spec 0/1/2 matches. Ctrl-C currently can fall through to 0 on the scan path — leave that; audit should still kill workers on SIGINT and then exit 1.

Do not catch-all `except Exception` around the merge. Merge bugs are fatal (exit 1).

## Testing

No live Claude/Cursor/Codex.

1. `strix audit --help` exits 0 and lists `--agent`. Dispatch: `sys.argv = ["strix", "audit", "--help"]` never calls `parse_arguments` / Docker.
2. Adapter argv frozen as in Adapters (claude / cursor-agent / codex). Assert `cursor` IDE binary is never chosen.
3. Default `--agent`: monkeypatch `PATH` with fake binaries; picks first of `claude`, `cursor-agent`/`agent`, `codex`.
4. Merge remint: two workers each with `vuln-0001` → parent has `vuln-0001` and `vuln-0002`, both titles kept.
5. Exit codes: findings → 2; no findings → 0; all jobs failed → 1.
6. Isolation helper: non-git path reports `sequential=True`; Codex worktree argv includes `--detach`. Mock `git`. Never assert a DIY worktree for Claude/Cursor.
7. Fake binary: `claude` script on `PATH` records argv and exits 0. Assert skip-permissions + `--mcp-config` + `--strict-mcp-config`. Finding merge is test 4.
8. `strix mcp --no-seed`: no coverage todos seeded.

## Out of scope reminders

`strix -n`, TUI, `create_agent` Docker graph, and `strix mcp` (as a user-facing command) stay as they are except `--no-seed`. `strix audit` is a third entry: coordinator + vendor CLIs + MCP per worker.

Deferred: `strix mcp --run-dir`, cloning repository URL targets, manager JSON skip/add, `strix view` title for nested worker run dirs.
