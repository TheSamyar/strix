---
name: hydra
description: Fast online login brute-forcer (HTTP form/basic, SSH, FTP, etc.). Use shell; keep task lists small.
---

# hydra CLI Playbook

Official docs: https://github.com/vanhauser-thc/thc-hydra

Run via the shell tool.

Canonical syntax:
`hydra -l <user> -P <wordlist> <target> <service>`

Common patterns:
- SSH: `hydra -l admin -P /usr/share/seclists/Passwords/common.txt ssh://target`
- HTTP POST form: `hydra -l admin -P wl.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"`
- HTTP basic: `hydra -L users.txt -P wl.txt target http-get /admin`

Critical correctness rules:
- ONLINE brute force — slow and noisy; lockouts are real. Use `-t 4` low concurrency
  and small, targeted wordlists (seclists is at /usr/share/seclists).
- The `F=` (failure string) for http-*-form must match the app's failed-login marker,
  or every attempt reads as success.
- Authorized targets only.

If uncertain: `site:github.com/vanhauser-thc/thc-hydra http-post-form`
