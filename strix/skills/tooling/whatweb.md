---
name: whatweb
description: Cheap tech fingerprint. Aggression 1 first. JSON when you need to parse.
---

# whatweb CLI Playbook

Official docs: https://github.com/urbanadventurer/WhatWeb

Canonical syntax:
`whatweb [options] <url>`

Agent-safe baseline:
`whatweb -a 1 --log-json=- --no-errors https://target.tld`

Common patterns:
- Stealth: `whatweb -a 1 https://target.tld`
- Aggressive: `whatweb -a 3 https://target.tld`
- JSON to stdout: `whatweb -a 1 --log-json=- --no-errors https://target.tld`

Critical correctness rules:
- Start `-a 1`. `-a 3+` is noisy and slow.
- MCP: `run_scanner(tool="whatweb", target="https://target.tld", extra_args=["-a", "1", "--no-errors"])`

If uncertain: `site:github.com/urbanadventurer/WhatWeb whatweb`
