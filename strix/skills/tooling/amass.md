---
name: amass
description: OWASP Amass deep subdomain enumeration (passive/active), config, and pipeline output.
---

# Amass CLI Playbook

Official docs:
- https://github.com/owasp-amass/amass
- https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md

Canonical syntax:
`amass <subcommand> [flags]`  (primary: `enum`)

High-signal flags (`amass enum`):
- `-d <domain>` target domain (repeatable), `-df <file>` domain list
- `-passive` passive-only (no DNS resolution against target)
- `-active` add active checks (zone transfers, cert grabbing)
- `-brute` brute-force subdomains, `-w <wordlist>` brute wordlist
- `-config <yaml>` config file (API keys for OTX, Shodan, VirusTotal, etc.)
- `-timeout <min>` overall cap
- `-o <file>` text output, `-json <file>` JSON output
- `-dir <path>` graph DB dir (state/reuse)
- `-nocolor` clean logs for parsing

Agent-safe baseline:
`amass enum -passive -d target.tld -timeout 15 -nocolor -json amass.json`

Common patterns:
- Passive OSINT (stealthy): `amass enum -passive -d target.tld -json amass.json`
- Active + brute (loud, authorized only): `amass enum -active -brute -d target.tld -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -json amass.json`
- Multi-domain: `amass enum -passive -df domains.txt -o amass.txt`
- With API keys: `amass enum -passive -config ~/.config/amass/config.yaml -d target.tld -json amass.json`

Critical correctness rules:
- `-passive` skips resolution — results may include dead hosts; validate live ones with `httpx`/`dnsx`.
- `-active`/`-brute` send traffic to target infra and are noisy — use only within authorized scope.
- Many high-value sources need API keys via `-config`; sparse passive results are often a config gap, not target reality.
- Amass can run long; always bound with `-timeout`.
- MCP: `run_scanner(tool="amass", target="target.tld", extra_args=["-passive", "-json", "amass.json"])` (maps to `amass enum -d <target> ...`; pass a bare domain, not a URL).

Usage rules:
- Prefer `-json` for deterministic parsing; complements `subfinder` (run both, merge, `sort -u`).
- Keep passive first; escalate to active/brute only when scope allows.

If uncertain: `site:github.com/owasp-amass/amass user_guide <flag>`
