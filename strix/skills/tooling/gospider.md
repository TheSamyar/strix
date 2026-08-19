---
name: gospider
description: Fast web crawler for URL/endpoint/JS discovery. Feeds targets to nuclei/ffuf/sqlmap.
---

# gospider CLI Playbook

Official docs: https://github.com/jaeles-project/gospider

Canonical syntax:
`gospider -s <url> [options]`

Agent-safe baseline:
`gospider -s https://target.tld -d 2 -c 5 -t 10`

Common patterns:
- Crawl + parse JS: `gospider -s https://target.tld -d 3 --js`
- Include subdomains + other sources: `gospider -s https://target.tld -a -w`
- Quiet URL list only: `gospider -s https://target.tld -q`

Critical correctness rules:
- Discovery only — it finds surface, it does not test for vulns. Pipe results into nuclei/ffuf/sqlmap.
- Bound with `-d` (depth) and `-c`/`-t` (concurrency) to stay polite.
- MCP: `run_scanner(tool="gospider", target="https://target.tld", extra_args=["-d", "2", "--js", "-q"])`

If uncertain: `site:github.com/jaeles-project/gospider gospider flags`
