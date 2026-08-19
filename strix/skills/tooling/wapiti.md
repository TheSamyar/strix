---
name: wapiti
description: Full web-app DAST scanner (SQLi, XSS, SSRF, file disclosure, misconfig). OSS Nessus/ZAP-class coverage.
---

# wapiti CLI Playbook

Official docs: https://wapiti-scanner.github.io/

Canonical syntax:
`wapiti -u <url> [options]`

Agent-safe baseline:
`wapiti -u https://target.tld --flush-session -f json -o /tmp/wapiti.json`

Common patterns:
- Quick scan: `wapiti -u https://target.tld --scope url -d 2`
- Specific modules: `wapiti -u https://target.tld -m sql,xss,ssrf,exec`
- Auth'd: `wapiti -u https://target.tld -H "Cookie: session=..."`

Critical correctness rules:
- Wapiti crawls then attacks — can be slow. Bound depth with `-d` and scope with `--scope`.
- Prefer JSON output (`-f json`) so findings parse cleanly.
- MCP: `run_scanner(tool="wapiti", target="https://target.tld", extra_args=["-m", "sql,xss", "-d", "2"])`
- Confirm hits manually; DAST false-positives on reflected content.

If uncertain: `site:wapiti-scanner.github.io wapiti modules`
