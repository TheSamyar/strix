---
name: sstimap
description: Server-side template injection detection. Detection first; no interactive shell unless proving RCE.
---

# SSTImap CLI Playbook

Official docs: https://github.com/vladko312/SSTImap

Canonical syntax:
`sstimap -u "<url_with_param>" [options]`

Agent-safe baseline (detect only):
`sstimap -u "https://target.tld/page?name=test" -l 1`

Common patterns:
- Level 1 detect: `sstimap -u "https://target.tld/page?name=test" -l 1`
- POST: `sstimap -u "https://target.tld/page" -d "name=test" -p name -l 1`
- Cookie: `sstimap -u "https://target.tld/page?name=test" -c "session=abc" -l 1`

Critical correctness rules:
- Mark the injection point with a parameter (`-p` if ambiguous).
- Start at `-l 1`. Escalate only after a hit.
- Do not drop into `--os-shell` unless you are proving a validated finding.
- MCP: `run_scanner(tool="sstimap", target="https://target.tld/page?name=test", extra_args=["-l", "1"])`

If uncertain: `site:github.com/vladko312/SSTImap sstimap`
