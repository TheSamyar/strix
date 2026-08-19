---
name: retire
description: retire.js scanning — flag known-vulnerable JavaScript/Node dependencies in source or built assets.
---

# retire.js CLI Playbook

Official docs:
- https://github.com/RetireJS/retire.js

Canonical syntax:
`retire [--path <dir>] [flags]`

High-signal flags:
- `--path <dir>` scan a directory (source tree or built JS/assets)
- `--js` / `--node` restrict to JS or Node scanners
- `--outputformat <json|text|cyclonedx>` output format
- `--outputpath <file>` write report to file
- `--severity <low|medium|high|critical>` minimum severity to report
- `--jsrepo <url>` / `--noirr` custom/offline vuln DB control
- `--exitwith 0` don't fail the process on findings (agent-friendly)

Agent-safe baseline:
`retire --path ./target-src --outputformat json --outputpath retire.json --exitwith 0`

Common patterns:
- Scan crawled/downloaded JS: `retire --path ./loot/js --js --outputformat json --outputpath retire_js.json`
- High-sev only: `retire --path ./repo --severity high --outputformat json --outputpath retire.json`

Critical correctness rules:
- retire.js takes a **local path**, not a URL — download/crawl target JS first (e.g. via `katana`/`gospider`) then scan the saved files.
- It matches library versions against a known-vuln DB; a hit is a *known CVE in a dependency*, still confirm the vulnerable code path is reachable/exploitable.
- Use `--exitwith 0` in agent runs so a non-zero exit on findings doesn't abort the pipeline.
- Complements `trufflehog` (secrets) and CVE tooling (`nuclei`, `vulnx`); retire is client-side JS dependency risk specifically.
- MCP: `run_scanner(tool="retire", target="./target-src", extra_args=["--outputformat", "json", "--exitwith", "0"])` (path, not URL)

If uncertain: `site:github.com/RetireJS/retire.js <flag> README`
