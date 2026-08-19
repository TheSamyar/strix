---
name: crlfuzz
description: CRLF injection probe against a URL. Silent JSON-friendly runs.
---

# crlfuzz CLI Playbook

Official docs: https://github.com/dwisiswant0/crlfuzz

Canonical syntax:
`crlfuzz -u <url> [options]`

Agent-safe baseline:
`crlfuzz -u https://target.tld -s`

Common patterns:
- Single URL: `crlfuzz -u https://target.tld -s`
- URL list: `crlfuzz -l urls.txt -s -o crlf.json`

Critical correctness rules:
- Confirm a hit with a follow-up request (header injection / response split). Do not file from scanner output alone.
- MCP: `run_scanner(tool="crlfuzz", target="https://target.tld", extra_args=["-s"])`

If uncertain: `site:github.com/dwisiswant0/crlfuzz crlfuzz`
