<div align="center">

# ShellCracker

### One command, one target: recon to shell, unattended.

A terminal-based exploitation pipeline that chains reconnaissance, exploit
matching, validation and firing into a single run. Give it one target IP and it
scans, selects candidate exploits, fires them through a reverse handler until a
session lands, verifies that session, and hands you an interactive shell.

![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Category](https://img.shields.io/badge/Category-Exploitation-e53935?style=for-the-badge)
![Engine](https://img.shields.io/badge/Engine-Metasploit%20(msfrpc)-2e7d32?style=for-the-badge)
![Use](https://img.shields.io/badge/Use-Authorized%20lab%20only-121212?style=for-the-badge)

</div>

<!-- Optional: drop a terminal screenshot here, e.g.
<div align="center"><img width="1600" alt="ShellCracker interface" src="PASTE_SCREENSHOT_URL" /></div>
-->

---

<div align="center">
<img src="assets/how-it-works.svg" alt="How it works: an animated diagram of the ShellCracker pipeline." width="840" />
</div>

## Overview

ShellCracker automates the full chain from a single target IP to a working
session. Instead of running `nmap`, `searchsploit` and Metasploit by hand and
wiring a reverse handler each time, you give it one address and it drives those
already-installed tools for you, logging each step along the way.

It is a thin orchestration layer: it does **not** contain or develop exploit
code of its own. Reconnaissance is delegated to `nmap`, candidate selection to
the Metasploit module database and Exploit-DB, and every attempt runs through
the Metasploit framework over `msfrpc`.

- **Zero-setup run** — `msfrpcd` is started automatically if it is not already
  running, and `LHOST` is detected from the route to the target, so a basic run
  needs no config editing.
- **Interactive handoff** — when a session is verified, ShellCracker opens the
  shell in a new terminal window and leaves you in it to type commands.
- **Turkish interface** — the user-facing output is in Turkish; the code,
  configuration and this README are in English.

---

## Methodology

<div align="center">
<img src="assets/methodology.svg" alt="ShellCracker methodology: target, recon, match, fire, shell." width="860" />
</div>

1. **Target** — start from a single lab IP you own or are authorized to test.
2. **Recon** — `nmap -sV -Pn` discovers open services and their versions.
3. **Match** — services are mapped to ranked candidate exploits from the
   Metasploit module database (with Exploit-DB hits for reference).
4. **Fire** — each candidate is validated with a `check()` dry-run where
   supported, then launched through `msfrpc` behind a reverse handler.
5. **Shell** — a landed session is verified with a harmless command, then
   handed to you interactively in a new terminal window.

Only a single explicitly provided IP is ever touched.

---

## Pipeline

| Stage | What happens |
|---|---|
| Recon | `nmap -sV -Pn`, XML parsed into structured services |
| Match | Metasploit module search + `searchsploit`, ranked by exploit reliability |
| Dry-run | module `check()` where supported; targets reported safe are skipped |
| Fire | compatible reverse payload selected, handler set up, candidates fired in order |
| Verify | a harmless command confirms the session and captures proof |
| Handoff | the interactive shell opens in a new terminal window |

---

## Safeguards

ShellCracker is built for **your own virtual machines and sanctioned training
environments** (Metasploitable, Hack The Box, TryHackMe, OSCP-style labs).

- **One IP only** — `--target` accepts a single IP address; CIDR, ranges, lists
  and input files are rejected. There is no mass-scanning mode.
- **No hardcoded targets** and **no internet-facing scan mode**.
- **Clean interrupt** — `Ctrl+C` stops immediately and tears down only the
  sessions ShellCracker itself opened.

Using it against systems you do not own or lack explicit written permission to
test is illegal in most jurisdictions. You are solely responsible for having
authorization.

---

## Architecture

```
Siber-ShellCracker/
├── shell.py              # entry: startup animation, banner, orchestration
├── attach.py             # standalone session attach (used by the new window)
├── core/
│   ├── recon.py          # nmap service/version discovery + XML parsing
│   ├── matcher.py        # services -> ranked candidate exploits
│   ├── executor.py       # msfrpc: auto-start, check(), fire, verify, cleanup
│   ├── interactive.py    # interactive bridge to a live session
│   ├── reporter.py       # JSON + Markdown report (optional)
│   └── colors.py         # dependency-free ANSI colouring
├── config.yaml.example   # copy to config.yaml (sane lab defaults)
├── requirements.txt
└── LICENSE
```

---

## Requirements

| Component | Notes |
|---|---|
| Python 3.12+ | with `python-nmap`, `pymetasploit3`, `PyYAML` |
| nmap, searchsploit | standard on Kali |
| Metasploit Framework | `msfconsole`, `msfrpcd`, `msfvenom` |
| Linux + root | nmap `-sV` and `msfrpcd` run best as root |
| Lab network access | a reachable target you are authorized to test |

---

## Installation

```bash
git clone https://github.com/osmnabyram/Siber-ShellCracker.git
cd Siber-ShellCracker

pip install -r requirements.txt
cp config.yaml.example config.yaml
```

Defaults work out of the box for a local lab: `handler.lhost` is `auto`
(detected from the route to the target) and `msfrpcd` is auto-started with the
user/password/port in `config.yaml` (default `msf` / `msf` / `55553`).

---

## Usage

Run it and enter the target when asked:

```bash
python3 shell.py
```

```text
Sistem aciliyor      Hosgeldiniz

                 S H E L L C R A C K E R

[?] Kurban IP (tek adres): 192.168.56.101
    Hedef: 192.168.56.101
    LHOST: 192.168.56.1  (otomatik)

═══[ KESIF ]═══ ...
═══[ ESLESTIRME ]═══ ...
═══[ SOMURU ]═══ ...

  ╔══════════════════════════════════════╗
  ║  SHELL ALINDI  —  oturum 1 (shell)
  ╚══════════════════════════════════════╝
```

On success the interactive shell opens in a **new terminal window** by default.
You can also pass the target non-interactively:

```bash
python3 shell.py --target 192.168.56.101
```

| Flag | Description |
|---|---|
| `--target <IP>` | Single target IP. CIDR/ranges/lists rejected. If omitted, you are prompted. |
| `--config <path>` | Config file (default `config.yaml`). |
| `--rapor` | Write JSON + Markdown report, logfile and raw nmap XML to `reports/` (off by default). |
| `--ayni-pencere` | Attach to the shell in THIS window instead of opening a new terminal. |

Exit codes: `0` success / clean no-op, `1` cancelled or error, `3` msfrpc
unreachable, `4` no shell obtained.

### Optional: start msfrpcd yourself

Auto-start covers the common case. To run the daemon manually (for example to
watch its output), start it first and ShellCracker will reuse it:

```bash
msfrpcd -U msf -P msf -p 55553 -a 127.0.0.1
```

---

## License

[MIT](LICENSE). Provided as-is, for authorized security education and testing.
