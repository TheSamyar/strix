---
name: gau
description: gau (getallurls) historical URL harvesting from Wayback/CommonCrawl/OTX with filtering and pipeline output.
---

# gau CLI Playbook

Official docs:
- https://github.com/lc/gau

Canonical syntax:
`gau [flags] [domain]`  (domain as arg, or domains via stdin)

High-signal flags:
- `--providers <wayback,commoncrawl,otx,urlscan>` select sources
- `--subs` include subdomains
- `--blacklist <ext,...>` drop noise (e.g. `png,jpg,css,woff,svg`)
- `--mc <codes>` / `--fc <codes>` match/filter by status (adds live checks)
- `--from <YYYYMM>` / `--to <YYYYMM>` date window
- `--threads <n>` concurrency
- `--proxy <url>` route requests
- `--o <file>` output file, `--json` JSON output

Agent-safe baseline:
`gau --subs --blacklist png,jpg,jpeg,gif,css,woff,woff2,svg,ico --threads 5 target.tld -o gau.txt`

Common patterns:
- Multi-domain from list: `cat domains.txt | gau --subs --threads 5 -o gau_all.txt`
- Feed XSS/param tools: `gau --subs target.tld | grep '=' | dalfox pipe --silence`
- Find params for arjun: `gau target.tld | grep -oP 'https?://[^?]+' | sort -u > gau_paths.txt`
- Recent only: `gau --from 202401 --subs target.tld -o gau_recent.txt`

Critical correctness rules:
- gau is passive OSINT — results are historical, so endpoints may be dead (404/redirect); validate with `httpx` before attacking.
- `--mc/--fc` make live requests (no longer purely passive); use deliberately.
- Always `--blacklist` static asset extensions or the output drowns real endpoints.
- De-dupe (`sort -u`) before piping downstream.
- MCP: `run_scanner(tool="gau", target="target.tld", extra_args=["--subs", "--blacklist", "png,jpg,css"])`

Usage rules:
- Pass a bare domain (no scheme) as the target.
- Keep `--threads` low; providers throttle.

Alternate tool: `waybackurls <domain>` (simpler, Wayback-only, no flags). Reach
for gau for multi-provider coverage and filtering; reach for waybackurls for a
quick single-source dump. Note: gau is in the run_scanner allowlist,
waybackurls is not — run waybackurls via plain CLI.

If uncertain: `site:github.com/lc/gau <flag> README`
