---
name: wafw00f
description: wafw00f WAF/CDN fingerprinting — identify the protection in front of a target before testing.
---

# wafw00f CLI Playbook

Official docs:
- https://github.com/EnableSecurity/wafw00f

Canonical syntax:
`wafw00f <url> [flags]`

High-signal flags:
- `<url>` target (or `-i <file>` for a list of URLs)
- `-a` test for ALL WAFs (don't stop at first match)
- `-v` / `-vv` verbosity
- `-p <proxy>` route through a proxy
- `-H <file>` extra headers file
- `-o <file> -f json` structured output (`-f csv|json|text`)
- `-l` list all WAFs wafw00f can detect

Agent-safe baseline:
`wafw00f https://target.tld -a -o wafw00f.json -f json`

Common patterns:
- Bulk: `wafw00f -i urls.txt -a -o waf.json -f json`
- Via proxy: `wafw00f https://target.tld -p http://127.0.0.1:48080 -a`

Critical correctness rules:
- Run this FIRST — knowing the WAF/CDN shapes payload encoding, rate, and evasion for every later tool.
- "No WAF detected" is not proof of absence; it means no known signature matched. Test accordingly.
- A detected WAF explains later 403/429 noise — tune `ffuf`/`dirsearch`/`sqlmap` rate and tamper instead of hammering.
- MCP: `run_scanner(tool="wafw00f", target="https://target.tld", extra_args=["-a"])`

If uncertain: `site:github.com/EnableSecurity/wafw00f <flag> README`
