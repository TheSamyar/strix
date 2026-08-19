---
name: john
description: John the Ripper — offline hash cracker (CPU). Feed hashes from responder/dumps. Use shell.
---

# john (John the Ripper) CLI Playbook

Official docs: https://www.openwall.com/john/

Run via the shell tool. Identify the hash first (`hashid <hash>`), then crack.

Canonical syntax:
`john --wordlist=<wordlist> --format=<fmt> hashes.txt`

Common patterns:
- Wordlist: `john --wordlist=/usr/share/seclists/Passwords/rockyou.txt hashes.txt`
- With rules: `john --wordlist=wl.txt --rules hashes.txt`
- Show cracked: `john --show --format=<fmt> hashes.txt`
- NetNTLMv2 from responder: `john --format=netntlmv2 hashes.txt`

Critical correctness rules:
- Wrong `--format` = it silently never cracks. Confirm with `hashid` / `john --list=formats`.
- CPU cracking — fine for fast/weak hashes; for GPU-heavy hashes prefer hashcat.
- `--show` reads results without re-running; results persist in ~/.john/john.pot.

If uncertain: `site:openwall.com/john format options`
