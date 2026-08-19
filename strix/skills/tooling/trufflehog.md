---
name: trufflehog
description: TruffleHog secret scanning (filesystem/git/GitHub) with verified-only filtering and JSON output.
---

# TruffleHog CLI Playbook

Official docs:
- https://github.com/trufflesecurity/trufflehog

Canonical syntax:
`trufflehog <source> <target> [flags]`

Sources:
- `filesystem <path>` local files/dirs (allowlisted in run_scanner)
- `git <repo_url_or_path>` full commit history
- `github --repo <url>` / `github --org <name>` remote GitHub
- `s3` / `gcs` / `docker --image <ref>` cloud & container images

High-signal flags:
- `--only-verified` keep only secrets confirmed live against the provider (kills most false positives)
- `--results=verified,unknown` control result classes
- `--json` structured output (one JSON object per finding)
- `--no-update` skip self-update (deterministic runs)
- `--concurrency <n>` workers
- `--include-paths <file>` / `--exclude-paths <file>` scope control
- `--since-commit <sha>` / `--branch <name>` bound git scans

Agent-safe baseline:
`trufflehog filesystem ./target-src --only-verified --no-update --json > trufflehog.json`

Common patterns:
- Full git history: `trufflehog git file://./repo --only-verified --no-update --json > th_git.json`
- Remote GitHub org: `trufflehog github --org acme --only-verified --no-update --json > th_org.json`
- Scan crawled JS/assets on disk: `trufflehog filesystem ./loot/js --json > th_js.json`
- Container image: `trufflehog docker --image target/app:latest --only-verified --json > th_img.json`

Critical correctness rules:
- `--only-verified` actually calls the secret's provider to confirm it's live — that is a network side effect; drop it (accept noise) if you must stay fully passive.
- Unverified findings are candidates, not confirmed leaks; triage before reporting.
- For repos, scan with `git` (history) not just `filesystem` — most leaked secrets live in old commits, not HEAD.
- `--no-update` keeps detector behavior reproducible across runs.
- MCP: `run_scanner(tool="trufflehog", target="./target-src", extra_args=["--only-verified", "--json"])` (filesystem mode; `target` is the path)

Usage rules:
- Emit `--json` for parsing; each line is a finding.
- Scope large trees with `--include-paths`/`--exclude-paths` to control runtime.

Alternate tool: `gitleaks detect --source <path> -f json -r gitleaks.json` —
config-driven regex rules, great for CI gates. Reach for trufflehog when you
want live verification and broad remote sources; reach for gitleaks for
fast rule-based repo/CI scanning. Note: trufflehog is in the run_scanner
allowlist, gitleaks is not — run gitleaks via plain CLI.

If uncertain: `site:github.com/trufflesecurity/trufflehog <flag> README`
