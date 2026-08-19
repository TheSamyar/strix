---
name: sslscan
description: TLS cipher and certificate scan. Prefer host:port, not a full URL.
---

# sslscan CLI Playbook

Official docs: https://github.com/rbsec/sslscan

Canonical syntax:
`sslscan [options] host[:port]`

Agent-safe baseline:
`sslscan --no-failed --no-colour target.tld:443`

Common patterns:
- HTTPS default port: `sslscan --no-failed target.tld`
- Explicit port: `sslscan --no-failed target.tld:8443`
- Show failed ciphers too: `sslscan target.tld:443`

Critical correctness rules:
- Pass `host` or `host:port`. Strip `https://`.
- MCP: `run_scanner(tool="sslscan", target="target.tld:443", extra_args=["--no-failed"])`
- Do not use `-h` during a scan.

If uncertain: `site:github.com/rbsec/sslscan sslscan`
