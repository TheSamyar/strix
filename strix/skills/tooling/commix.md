---
name: commix
description: Command injection detection. Always --batch. Detection first, no interactive shell unless proving RCE.
---

# commix CLI Playbook

Official docs: https://github.com/commixproject/commix/wiki

Canonical syntax:
`commix -u "<url_with_param>" --batch [options]`

Agent-safe baseline:
`commix -u "https://target.tld/ping?host=127.0.0.1" --batch --level 1`

Common patterns:
- GET: `commix -u "https://target.tld/ping?host=127.0.0.1" --batch --level 1`
- POST: `commix -u "https://target.tld/ping" --data="host=127.0.0.1" --batch --level 1`
- Cookie: `commix -u "https://target.tld/ping?host=1" --cookie="session=abc" --batch`

Critical correctness rules:
- Always `--batch` (baked into `run_scanner`).
- Start `--level 1`. Escalate only after a hit.
- Do not use `--os-shell` unless proving a validated finding.
- MCP: `run_scanner(tool="commix", target="https://target.tld/ping?host=1", extra_args=["--level", "1"])`

If uncertain: `site:github.com/commixproject/commix/wiki commix`
