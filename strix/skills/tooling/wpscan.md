---
name: wpscan
description: WordPress enumeration. Detection and version/plugin listing; no unsolicited brute-force.
---

# wpscan CLI Playbook

Official docs: https://github.com/wpscanteam/wpscan

Canonical syntax:
`wpscan --url <url> [options]`

Agent-safe baseline:
`wpscan --url https://target.tld --enumerate vp --plugins-detection mixed --random-user-agent`

Common patterns:
- Version + plugins: `wpscan --url https://target.tld --enumerate vp`
- Users: `wpscan --url https://target.tld --enumerate u`
- API token (if set): `wpscan --url https://target.tld --api-token "$WPSCAN_API_TOKEN" --enumerate vp`

Critical correctness rules:
- Do not `--passwords` / brute users unless the user explicitly asked.
- MCP: `run_scanner(tool="wpscan", target="https://target.tld", extra_args=["--enumerate", "vp"])`

If uncertain: `site:github.com/wpscanteam/wpscan wpscan`
