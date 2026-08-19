---
name: hashid
description: Identify a hash type. Pass the hash string, not a URL.
---

# hashid CLI Playbook

Official docs: https://github.com/psypanda/hashID

Canonical syntax:
`hashid [options] <hash>`

Agent-safe baseline:
`hashid -j '$1$abc$def'`

Common patterns:
- One hash: `hashid '$1$abc$def'`
- JSON: `hashid -j '$1$abc$def'`
- File of hashes: `hashid -j hashes.txt`

Critical correctness rules:
- Quote hashes so `$` does not expand in the shell.
- MCP: `run_scanner(tool="hashid", target="$1$abc$def", extra_args=["-j"])` (no shell, quoting not needed)
- Identification is not cracking. Do not run john/hashcat unless the user asks.

If uncertain: `site:github.com/psypanda/hashID hashid`
