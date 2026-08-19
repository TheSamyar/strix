---
name: dnsx
description: dnsx fast DNS toolkit — resolution, record types, wildcard filtering, and subdomain validation.
---

# dnsx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/dnsx/usage
- https://github.com/projectdiscovery/dnsx

Canonical syntax:
`dnsx [flags]`  (domains via `-d`, or a host list on stdin / `-l <file>`)

High-signal flags:
- `-d <domain>` domain(s), `-l <file>` list of hosts to resolve
- `-a -aaaa -cname -mx -ns -txt -ptr -soa` record types to query
- `-resp` show the resolved record value (not just the name)
- `-re` / `-recon` all records at once
- `-w <wordlist> -d <domain>` DNS brute (with `{domain}` templating)
- `-wd <domain>` wildcard filtering domain (drops wildcard noise)
- `-rl <n>` rate limit, `-t <n>` threads
- `-silent` compact, `-json` JSONL, `-o <file>` output

Agent-safe baseline:
`dnsx -l hosts.txt -a -resp -silent -json -o dnsx.jsonl`

Common patterns:
- Validate subfinder output (live hosts): `subfinder -d target.tld -silent | dnsx -silent -a -resp -o resolved.txt`
- Record recon: `dnsx -d target.tld -re -json -o dnsx_records.jsonl`
- DNS brute w/ wildcard filter: `dnsx -d target.tld -w subs.txt -wd target.tld -silent -o brute.txt`

Critical correctness rules:
- dnsx resolves/validates — it is the live-check step after passive enum (`subfinder`/`amass`/`gau`); pipe those in.
- Always set `-wd` when brute-forcing or wildcard DNS produces mass false positives.
- `-resp` is needed to capture the actual record value; without it you only get names.
- Keep `-rl` modest against a single resolver; use `-r <resolvers.txt>` for trusted resolvers.
- MCP: `run_scanner(tool="dnsx", target="target.tld", extra_args=["-a", "-resp", "-silent"])` (bare domain, not a URL)

If uncertain: `site:docs.projectdiscovery.io dnsx <flag> usage`
