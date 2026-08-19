---
name: arjun
description: Arjun hidden HTTP parameter discovery syntax with method control, wordlists, and JSON output.
---

# Arjun CLI Playbook

Official docs:
- https://github.com/s0md3v/Arjun

Canonical syntax:
`arjun -u <url> [flags]`

High-signal flags:
- `-u <url>` target (single), `-i <file>` list of URLs
- `-m <GET|POST|JSON|XML>` request method to test
- `-w <wordlist>` custom parameter wordlist
- `-c <n>` chunk size (params per request; lower if backend caps)
- `-d <seconds>` delay between requests
- `-t <n>` threads
- `--headers "K: V"` custom headers/auth
- `--stable` slower but more reliable (reduces false negatives on flaky targets)
- `-oJ <file>` / `-oT <file>` JSON / text output
- `--passive` mine params from passive sources (gau/wayback/commoncrawl)

Agent-safe baseline:
`arjun -u https://target.tld/endpoint -m GET -t 5 -d 100 --stable -oJ arjun.json`

Common patterns:
- POST/JSON API: `arjun -u https://target.tld/api/user -m JSON --headers "Authorization: Bearer ..." -oJ arjun.json`
- Bulk from harvested paths: `arjun -i gau_paths.txt -m GET -oJ arjun_bulk.json`
- Passive mining: `arjun -u https://target.tld/ --passive -oJ arjun_passive.json`
- Custom wordlist: `arjun -u https://target.tld/search -w params.txt -m GET -oJ arjun.json`

Critical correctness rules:
- Arjun infers params by diffing responses — pick the right `-m` (GET vs POST vs JSON); wrong method = wrong/empty results.
- On heuristic-noisy targets use `--stable`; a single reflected param can otherwise mask others.
- Lower `-c` if the server rejects large query strings (414/400).
- Discovered params are candidates — feed them to `dalfox`/`sqlmap`/manual testing to confirm impact.
- MCP: `run_scanner(tool="arjun", target="https://target.tld/endpoint", extra_args=["-m", "GET", "--stable"])`

Usage rules:
- Keep `-t` low and add `-d` when the target throttles.
- Prefer `-oJ` for deterministic parsing.

If uncertain: `site:github.com/s0md3v/Arjun <flag> README`
