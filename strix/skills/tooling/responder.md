---
name: responder
description: LLMNR/NBT-NS/mDNS poisoner — captures NetNTLM hashes on a local network. Long-running; use shell tty.
---

# responder CLI Playbook

Official docs: https://github.com/lgandx/Responder

Long-running listener — start it via the shell tool with tty=true so you can stop it.

Start:
`exec_command(cmd="responder -I <iface> -wv", tty=true)`
Stop: send Ctrl-C via `write_stdin`.

Common patterns:
- Analyze mode (listen only, no poisoning): `responder -I eth0 -A`
- Full capture: `responder -I eth0 -wv`
- Captured hashes land in `/usr/share/responder/logs/` — cat them, then crack with john/hashcat.

Critical correctness rules:
- Needs an L2-adjacent network to be useful; useless against a single remote web target.
- Poisoning is intrusive and noisy — analyze mode (`-A`) first to confirm traffic.
- Only run on networks you are authorized to test.

If uncertain: `site:github.com/lgandx/Responder usage`
