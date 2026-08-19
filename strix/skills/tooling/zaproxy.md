---
name: zaproxy
description: OWASP ZAP headless DAST (active + passive web-app scan). Run via shell; read the report file after.
---

# zaproxy (OWASP ZAP) CLI Playbook

Official docs: https://www.zaproxy.org/docs/

Not a run_scanner tool — ZAP writes a report FILE, so drive it via the shell tool
and then cat the report.

Headless quick scan:
`zaproxy -cmd -quickurl https://target.tld -quickprogress -quickout /tmp/zap.json`
then: `cat /tmp/zap.json`

Baseline (passive, fast, low-risk) if the packaged script is present:
`zap-baseline.py -t https://target.tld -J /tmp/zap.json` then `cat /tmp/zap.json`

Common patterns:
- Quick active scan: `-quickurl <url> -quickout /tmp/zap.json` (JSON by extension)
- HTML report: `-quickout /tmp/zap.html`
- Ajax spider heavy SPA: add `-quickajax` (slower, better coverage)

Critical correctness rules:
- ZAP is a JVM app — first launch is slow; give shell commands a generous timeout.
- The active scan is INTRUSIVE (sends attack payloads). Use `zap-baseline.py` for a
  passive-only pass when you must stay low-noise.
- Report goes to a FILE; you must cat it to see findings. `-quickprogress` prints
  progress to stdout so you can tell it is alive.
- Confirm hits manually; DAST false-positives on reflected input.

If uncertain: `site:zaproxy.org command line quick scan`
