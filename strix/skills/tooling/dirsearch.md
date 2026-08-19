---
name: dirsearch
description: dirsearch content/path discovery with curated wordlists, extension expansion, and structured output.
---

# dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch

Canonical syntax:
`dirsearch -u <url> [flags]`

High-signal flags:
- `-u <url>` target (or `-l <file>` for a URL list)
- `-e <exts>` extensions to append (e.g. `php,html,js,json,bak`)
- `-w <wordlist>` custom wordlist (defaults to bundled `db/dicts.txt`)
- `-x <codes>` exclude status codes (e.g. `404,403`), `-i <codes>` include only
- `-r` recursive, `-R <depth>` recursion depth
- `-t <n>` threads, `--delay <s>` throttle
- `-H "K: V"` headers/auth, `--cookie "..."`
- `--proxy <url>` route through Burp/ZAP
- `--plain-text-report <file>` / `--json-report <file>` structured output
- `--full-url` print absolute URLs (pipeline-friendly)

Agent-safe baseline:
`dirsearch -u https://target.tld -e php,html,js,json -x 404,403 -t 20 --full-url --json-report dirsearch.json`

Common patterns:
- Recursive dir map: `dirsearch -u https://target.tld -r -R 2 -x 404 --json-report dirsearch.json`
- Authed: `dirsearch -u https://target.tld -H "Cookie: session=..." -e php,json`
- Via proxy: `dirsearch -u https://target.tld --proxy http://127.0.0.1:48080 -x 404`

Critical correctness rules:
- dirsearch ships curated wordlists + sane defaults — reach for it for a quick broad sweep; reach for `ffuf` for surgical input-position fuzzing or precise matcher control.
- Filter noise with `-x` (exclude) rather than raising load; soft-404 pages inflate results — verify hits.
- Prefer `--json-report`/`--plain-text-report` for deterministic parsing.
- MCP: `run_scanner(tool="dirsearch", target="https://target.tld", extra_args=["-e", "php,json", "-x", "404"])`

If uncertain: `site:github.com/maurosoria/dirsearch <flag> README`
