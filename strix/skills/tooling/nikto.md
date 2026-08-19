---
name: nikto
description: Classic web misconfig scanner. Noisy. Prefer nuclei first; nikto as a second pass.
---

# nikto CLI Playbook

Official docs: https://github.com/sullo/nikto

Canonical syntax:
`nikto -host <url> [options]`

Agent-safe baseline:
`nikto -host https://target.tld -Tuning 1 -nointeractive`

Common patterns:
- Light: `nikto -host https://target.tld -Tuning 1 -nointeractive`
- SSL host: `nikto -host target.tld -ssl -port 443 -nointeractive`

Critical correctness rules:
- Prefer `nuclei` for CVE/misconfig. Use nikto when you want the older CGI/file checks nuclei missed.
- MCP: `run_scanner(tool="nikto", target="https://target.tld", extra_args=["-Tuning", "1", "-nointeractive"])`
- Confirm hits. Nikto false-positives a lot.

If uncertain: `site:github.com/sullo/nikto nikto`
