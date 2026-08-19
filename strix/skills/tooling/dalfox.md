---
name: dalfox
description: dalfox XSS scanner/parameter-analysis syntax with modes, matcher control, and non-interactive output.
---

# dalfox CLI Playbook

Official docs:
- https://github.com/hahwul/dalfox

Canonical syntax:
`dalfox <mode> <target> [flags]`

Modes:
- `url <url>` scan a single URL
- `pipe` read URLs from stdin (chain from `gau`/`katana`/`waybackurls`)
- `file <urls.txt>` scan a URL list
- `sxss <url>` stored-XSS mode

High-signal flags:
- `-p <param>` restrict to a parameter
- `-b <collab_url>` blind-XSS callback (interactsh/your host)
- `-H <header>` custom headers, `-C <cookie>` cookies
- `--custom-payload <file>` add payloads
- `--mining-dict` / `--mining-dom` parameter mining
- `--skip-bav` skip basic-auth/verification noise
- `--worker <n>` concurrency, `--delay <ms>` throttle
- `--proxy <url>` route through Burp/ZAP
- `-o <file>` output, `--format json` / `--only-poc` structured/PoC output
- `--silence` compact output

Agent-safe baseline:
`dalfox url https://target.tld/?q=1 --worker 20 --delay 100 --skip-bav --silence --format json -o dalfox.json`

Common patterns:
- Pipe from URL harvester: `gau target.tld | dalfox pipe --silence --format json -o dalfox.json`
- Single param, blind callback: `dalfox url 'https://target.tld/s?q=1' -p q -b https://xss.report/c/you --silence`
- Authed scan via proxy: `dalfox url https://target.tld/app -C 'session=...' --proxy http://127.0.0.1:48080 --silence`
- Param mining: `dalfox url https://target.tld/page --mining-dict --mining-dom --silence --format json -o dalfox.json`

Critical correctness rules:
- The target must contain the injection point; use `pipe`/`file` for bulk endpoints from `gau`.
- Prefer `--format json` for deterministic parsing; `--only-poc` when you just need reproducible payloads.
- Blind XSS needs a reachable `-b` callback — without it, stored/blind hits are missed, not absent.
- Confirm reflected/DOM hits manually; verify the PoC fires in a real browser context.
- MCP: `run_scanner(tool="dalfox", target="https://target.tld/?q=1", extra_args=["--silence", "--format", "json"])`

Usage rules:
- Start conservative (`--worker`, `--delay`) and scale only if target tolerance is known.
- Do not use `-h`/`--help` during normal execution unless necessary.

If uncertain: `site:github.com/hahwul/dalfox <flag> README`
