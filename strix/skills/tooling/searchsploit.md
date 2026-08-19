---
name: searchsploit
description: Local Exploit-DB lookup. Search by product and version, not a URL.
---

# searchsploit CLI Playbook

Official docs: https://www.exploit-db.com/searchsploit

Canonical syntax:
`searchsploit [options] <query>`

Agent-safe baseline:
`searchsploit -j apache 2.4.49`

Common patterns:
- JSON: `searchsploit -j wordpress 6.4`
- Title-only: `searchsploit -t openssl`
- Exact: `searchsploit --exact "Apache 2.4.49"`

Critical correctness rules:
- `target` is the search query, not a URL.
- JSON (`-j`) is easier to parse than the table.
- MCP: `run_scanner(tool="searchsploit", target="apache 2.4.49", extra_args=["-j"])`
- A listing is not a finding. Prove the target is actually vulnerable.

If uncertain: `site:www.exploit-db.com searchsploit`
