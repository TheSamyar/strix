---
name: metasploit
description: Exploitation framework. Drive msfconsole non-interactively (-x) or via the shell tool with tty=true.
---

# metasploit CLI Playbook

Official docs: https://docs.metasploit.com/

Run it two ways — NOT via run_scanner (it is interactive/stateful). Use the shell tool.

Non-interactive one-shot (preferred for automation):
`msfconsole -q -x "use <module>; set RHOSTS <target>; set RPORT <port>; run; exit"`

Interactive (for multi-step sessions, meterpreter):
- `exec_command(cmd="msfconsole -q", tty=true)` then `write_stdin` each command line.

Common patterns:
- Search: `msfconsole -q -x "search type:exploit <cve-or-product>; exit"`
- Check (safe, no exploit): `... set RHOSTS t; check; exit`
- Payload only: `msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <fmt> -o out`
- Aux scanner: `msfconsole -q -x "use auxiliary/scanner/<x>; set RHOSTS t; run; exit"`

Critical correctness rules:
- Prefer `check` over `run` first — confirm the target is vulnerable before firing.
- Scope: only fire exploits against authorized targets; the operator owns scope.
- `-q` silences the banner; always end scripts with `exit` or the process hangs.
- Long jobs / handlers: use tty=true so you can Ctrl-C via write_stdin.

If uncertain: `site:docs.metasploit.com msfconsole resource scripts`
