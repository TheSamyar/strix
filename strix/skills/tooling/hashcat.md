---
name: hashcat
description: GPU-accelerated hash cracker. CPU-only in this sandbox (slower) — use for fast hashes or short wordlists.
---

# hashcat CLI Playbook

Official docs: https://hashcat.net/wiki/

Run via the shell tool. Identify hash mode first (`hashid`, or hashcat --help | grep).

Canonical syntax:
`hashcat -m <mode> -a 0 hashes.txt <wordlist>`

Common patterns:
- MD5 wordlist: `hashcat -m 0 -a 0 hashes.txt /usr/share/seclists/Passwords/rockyou.txt`
- NTLM: `hashcat -m 1000 -a 0 hashes.txt wl.txt`
- NetNTLMv2 (from responder): `hashcat -m 5600 -a 0 hashes.txt wl.txt`
- With rules: add `-r /usr/share/hashcat/rules/best64.rule`
- Show cracked: `hashcat -m <mode> hashes.txt --show`

Critical correctness rules:
- This sandbox is CPU-only (no GPU): add `-D 1` (CPU device) and expect it to be
  slow — keep wordlists short or prefer john for CPU work.
- Wrong `-m` mode = never cracks. Match the mode to the hash exactly.
- Potfile caches results; `--show` reprints without recracking.

If uncertain: `site:hashcat.net/wiki example hashes` (mode reference)
