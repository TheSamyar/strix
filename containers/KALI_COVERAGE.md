# Kali tool coverage

Living checklist. Source: [kali.org/tools](https://www.kali.org/tools/). Image: `containers/Dockerfile` (`kalilinux/kali-rolling`).

We are **not** Kali. We are a web / API / source pentest sandbox on a Kali base.

When you add or drop a package in the Dockerfile, flip the status here in the same PR.

| Status | Meaning |
| --- | --- |
| **HAVE** | Installed in the image (apt / pipx / go / npm / git) |
| **WANT** | Should add. Web/API/source gap. |
| **SKIP** | Do not add. Reason in the row. |

Skip reasons: `dup` (we already have a better equivalent) · `hw` (WiFi / BT / RF / NFC) · `gui` · `c2` (C2 / malware / payloads) · `ad` (AD / Windows internals) · `for` (forensics) · `voip` · `phish` · `old` · `scope` (not our product)

---

## WANT (add these)

Nothing P0 left. Next only if an engagement actually needs it:

| Tool | Why |
| --- | --- |
| linpeas | Post-RCE confirmation on the *target*, not the sandbox. Copy onto a box you already own. |

Do **not** expand WANT without a real engagement that needed it.

MCP host (no Docker): binaries must be on PATH. `run_scanner` returns `"not installed"` otherwise. Skills still load.

---

## HAVE (in the image)

Kali-catalog tools:

| Tool | How |
| --- | --- |
| nmap, ncat, ndiff | apt |
| sqlmap | apt |
| nuclei | apt |
| subfinder | apt |
| naabu | apt (Kali lists nmap/masscan; this is our port scanner) |
| ffuf | apt |
| seclists | apt (`$SECLISTS` = `/usr/share/seclists`) |
| exploitdb (searchsploit) | apt |
| sslscan | apt |
| sstimap | apt |
| commix | apt |
| wpscan | apt |
| whatweb | apt |
| nikto | apt |
| hashid | apt |
| crlfuzz | go |
| arjun | pipx |
| dirsearch | pipx |
| wafw00f | pipx |
| gospider | go |
| caido-cli | tarball |
| wapiti | apt |
| gdb | apt |
| trufflehog | install.sh |
| netcat-traditional | apt |

Not on the Kali catalog, also in the image:

httpx, katana, vulnx, interactsh-client, govulncheck, jwt_tool, semgrep, bandit, trivy, gitleaks, retire, eslint, js-beautify, jshint, ast-grep, tree-sitter, agent-browser, JS-Snooper, jsniper, chromium

Not in the image (older sandbox docs were wrong): ZAP, Playwright. Caido + agent-browser cover that job.

Native Strix wrappers (Python, not Kali packages): `nuclei_scan`, `gitleaks_scan`, `osv_scan`, `npm_audit`, `run_scanner` (MCP + host), proxy/Caido, agent_browser, shell.

This MCP-first fork does not start Docker. HAVE = the sandbox image for `strix -n`, not the host.

---

## SKIP (don't add)

Whole Kali categories we will not ship:

- WiFi / Bluetooth / RF / NFC / VoIP
- Forensics / carving / imaging
- C2 frameworks, payload gens, webshell kits, phishing kits
- AD / pass-the-hash / Kerberos / BloodHound
- GUI clones of a CLI we already have
- DoS / flood tools
- Lab start scripts (`dvwa-start`, `juice-shop-start`, `gvm-start`, …)

---

## Full Kali catalog

Deduped. First category on [kali.org/tools](https://www.kali.org/tools/) wins.

### Reconnaissance

| Tool | Status |
| --- | --- |
| metagoofil | SKIP scope |
| spiderfoot, spiderfoot-cli | SKIP scope (heavy OSINT) |
| email2phonenumber, emailharvester, instaloader, linkedin2username | SKIP scope |
| photon | SKIP dup (katana/gospider) |
| sherlock, tookie-osint | SKIP scope |
| amass | SKIP dup (subfinder) |
| autorecon | SKIP dup (nmap + naabu + httpx) |
| dmitry | SKIP old |
| legion, zenmap | SKIP gui |
| nmap | HAVE |
| theHarvester | SKIP scope |
| unicornscan | SKIP dup (nmap/naabu) |
| dnsmap, dnsrecon, dnsenum, massdns, dnstracer, dnswalk | SKIP dup (nmap + subfinder) |
| assetfinder, findomain, sublist3r | SKIP dup (subfinder) |
| arjun | HAVE |
| dirb, dirbuster, feroxbuster, gobuster, wfuzz | SKIP dup (ffuf) |
| dirsearch | HAVE |
| ffuf | HAVE |
| finalrecon, recon-ng | SKIP dup |
| gobuster | SKIP dup (ffuf) |
| gospider | HAVE |
| lbd, parsero, urlcrazy, uro, wpprobe | SKIP scope |
| subfinder | HAVE |
| uniscan-gui | SKIP gui |
| CAT, gvm-start, heartleech, owasp-mantra-ff | SKIP scope |
| burpsuite | SKIP gui (caido) |
| caido, caido-cli | HAVE (cli) |
| crlfuzz | HAVE |
| davtest | SKIP scope |
| joomscan | SKIP scope (add if we do Joomla) |
| nikto | HAVE |
| nuclei | HAVE |
| paros, skipfish, watobo, webscarab | SKIP old |
| sstimap | HAVE |
| subjack | SKIP dup (nuclei takeover templates) |
| tinja | SKIP dup (sstimap) |
| wapiti | HAVE |
| wcvs | SKIP scope |
| whatweb | HAVE |
| wpscan | HAVE |
| zaproxy | SKIP gui (caido + nuclei) |
| bettercap | SKIP hw |
| bluelog, bluesnarfer, btscanner, blueranger, fang, spooftooph, ubertooth-util | SKIP hw |
| asleap, kismet, sparrow-wifi, wash | SKIP hw |
| hackrf_info, gnuradio, gqrx, chirp, rfcat | SKIP hw |
| maltego | SKIP gui |

### Resource development

| Tool | Status |
| --- | --- |
| code-oss, clang, clang++, pyinstaller, wixl | SKIP scope |
| donut, sickle-pdk, msfvenom, msfpc, shellnoob, shellter, veil | SKIP c2 |
| wmic, wmis | SKIP ad |
| olevba, olefile | SKIP scope |
| afl-fuzz, bed, sfuzz, generic_* | SKIP scope |
| msf-nasm_shell | SKIP c2 |
| edb, ollydbg, gef | SKIP gui / RE |
| gdb | HAVE |
| cstool, ghidra, radare2, rizin, cutter, recstudio, recstudio-cli | SKIP scope (RE) |
| apktool, bytecode-viewer, jadx-gui, javasnoop, jd-gui, d2j-dex2jar | SKIP scope (mobile RE) |
| pompem | SKIP old |
| searchsploit | HAVE |
| exploitdb-papers | HAVE (with searchsploit / exploitdb) |

### Initial access / execution / persistence / privesc

| Tool | Status |
| --- | --- |
| dns-rebind | SKIP scope |
| gophish-start, setoolkit | SKIP phish |
| metasploit-framework, armitage | SKIP c2 |
| sqlmap | HAVE |
| sqlninja, sqlsus, jsql | SKIP dup (sqlmap) |
| commix | HAVE |
| jboss-linux, jboss-win | SKIP old |
| evilgrade, beef-xss-start, xsser | SKIP c2 |
| nishang, powersploit | SKIP ad |
| laudanum, phpggc, webacoo, webshells, weevely, backdoor-factory, cymothoa | SKIP c2 |
| seclists | HAVE |
| lynis | SKIP scope (hardening audit) |
| peass, linpeas | WANT (linpeas only, P1) |
| winpeas | SKIP ad |
| unix-privesc-check | SKIP dup (linpeas) |
| bloodyad | SKIP ad |

### Defense evasion / credential access

| Tool | Status |
| --- | --- |
| crackmapexec, netexec, evil-winrm, evil-winrm-py, impacket-scripts, mimikatz, passing-the-hash, rubeus, smbmap, xfreerdp3 | SKIP ad |
| sniffjoke, ftest, fragrouter, macchanger | SKIP scope |
| outguess, steghide, stegosuite, stegsnow | SKIP scope |
| exe2hex, ccrypt, padbuster | SKIP scope |
| chntpw, creddump7, samdump2 | SKIP ad |
| hashid | HAVE |
| hash-identifier | SKIP dup (hashid) |
| bopscrk, cewl, crunch, maskgen, policygen, rsmangler, statsgen, twofi | SKIP scope |
| wordlists | SKIP dup (seclists) |
| hydra, hydra-gtk, medusa, ncrack, patator, crowbar, legba, sqldict, thc-pptp-bruter | SKIP scope (no unsolicited brute) |
| hashcat, john, johnny, ophcrack, ophcrack-cli, rcrack, rcracki_mt, sipcrack, sucrack, truecrack, cmospwd, crackle, fcrackzip | SKIP scope (no GPU; not our job) |
| gitxray | SKIP dup (gitleaks/trufflehog) |
| trufflehog | HAVE |
| aircrack-ng, airgeddon, bully, cowpatty, eapmd5pass, fern-wifi-cracker, freeradius, pixiewps, reaver, wifi-honey, wifiphisher, wifite | SKIP hw |
| xspy | SKIP scope (keylogger) |
| svcrack, enumiax | SKIP voip |
| mfcuk, mfoc, mfterm, mifare-classic-format, nfc-list, nfc-mfclassic | SKIP hw |
| kerberoast, krbrelayx, responder | SKIP ad |

### Discovery / lateral / collection

| Tool | Status |
| --- | --- |
| masscan, sctpscan, unicornscan, ike-scan | SKIP dup (nmap/naabu) |
| sslscan | HAVE |
| sslyze, tlssled | SKIP dup (sslscan) |
| snmp-check, braa, onesixtyone | SKIP scope |
| wireshark | SKIP gui |
| tcpdump, scapy, tcpflow, netsniff-ng, dsniff, arpspoof, darkstat, dnschef, driftnet, hexinject, above | SKIP scope |
| arping, arpwatch, fierce, fping, hping3, p0f, atk6-thcping6, iputils-arping | SKIP dup (nmap) |
| apache-users, smtp-user-enum | SKIP scope |
| enum4linux, enum4linux-ng, nbtscan, smbclient | SKIP ad |
| pspy, pspy-binaries | SKIP scope |
| netdiscover, yersinia, firewalk, tcpreplay, 0trace.sh, ass, cdp, intrace, netmask, sara | SKIP scope |
| mysql, sqlitebrowser, mdb-sql, oscanner, sidguess, tnscmd10g, impacket-mssqlclient | SKIP scope |
| mxcheck, swaks | SKIP scope |
| cisco-* | SKIP scope |
| bloodhound, azurehound, sharphound, ldeep, bloodhound-python, bloodhound-ce-python | SKIP ad |
| all VoIP tools | SKIP voip |
| impacket-smbexec, impacket-psexec, rdesktop | SKIP ad |
| httrack | SKIP dup (katana) |
| ettercap, mitmproxy, mitm6, evilginx2, fluxion, wifipumpkin3, ssldump, sslsplit, sslsniff, fiked, ferret-sidejack, hamster-sidejack | SKIP dup (caido) / phish / hw |

### C2 / exfil / impact

| Tool | Status |
| --- | --- |
| ncat | HAVE |
| netcat | HAVE |
| socat, chisel, proxychains4, sshuttle, stunnel4, ligolo-*, dns2tcp*, dnscat, iodine, pwnat, ptunnel, proxytunnel, sslh, udptunnel, miredo, cadaver, minicom, dbd, sbd, powercat, penelope, termineter | SKIP c2 |
| adaptix*, havoc, hoaxshell, koadic, powershell-empire, starkiller-start, villain, armitage | SKIP c2 |
| impacket-smbserver, goshs, raven | SKIP c2 |
| dhcpig, goldeneye, iaxflood, inviteflood, mdk3, rtpflood, siege, slowhttptest, t50, thc-ssl-dos | SKIP scope (DoS) |

### Forensics / services / other

All **SKIP** (`for` / `gui` / lab start scripts): autopsy, binwalk, foremost, testdisk, sleuthkit, yara, rkhunter, chkrootkit, and the rest of that Kali section.

Reporting GUIs (maltego, faraday, dradis, cherrytree, obsidian, eyewitness, cutycapt, witnessme): SKIP gui. We write markdown / SARIF ourselves.

`gemini-cli`, `shell-gpt`, `hexstrike_server`, `code-oss`: SKIP scope.
