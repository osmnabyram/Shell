# ShellCracker

> Autonomous, single-target exploitation pipeline for **authorized lab use only**.

ShellCracker chains reconnaissance, exploit matching, validation and firing into
one CLI run. Given a single target IP, it scans with nmap, matches discovered
services against the Metasploit module database (and Exploit-DB for reference),
validates candidates, fires them through a reverse handler until a session
lands, verifies the session, and writes a full report.

It is a thin orchestration layer over tools that already ship with Kali Linux
(`nmap`, `searchsploit`, Metasploit via `msfrpcd`). It does **not** contain or
develop exploit code of its own.

---

## ⚠️ Authorized lab use only

ShellCracker is built for **your own virtual machines and sanctioned training
environments** (Metasploitable, TryHackMe, Hack The Box, OSCP-style labs). Using
it against systems you do not own or lack **explicit written permission** to test
is illegal in most jurisdictions.

Tool-level safeguards:

- **One IP only.** `--target` accepts a single IP address. CIDR, ranges, lists
  and input files are rejected. There is no mass-scanning mode.
- **Explicit consent gate.** Every run asks whether the target is yours / you
  are authorized, and the answer is recorded in the log and report.
- **No hardcoded targets** and **no internet-facing scan mode**.
- **Clean interrupt.** `Ctrl+C` stops immediately and tears down only the
  sessions ShellCracker itself opened.

You are solely responsible for having authorization.

---

## Features

- 🔍 **Recon** — `nmap -sV -Pn` with XML parsing into structured services; raw
  XML saved for audit.
- 🧩 **Match** — services → candidate exploits from the Metasploit module DB,
  ranked by reliability; Exploit-DB hits included in the report for reference.
- 🧪 **Dry-run** — runs each module's `check()` where supported and skips targets
  reported as not vulnerable.
- 🎯 **Fire** — selects a compatible reverse payload, sets up the handler
  (LHOST/LPORT), and fires candidates in order (configurable attempt limit and
  delay).
- 🐚 **Verify** — confirms a landed session by running a harmless command and
  captures the output as proof.
- 📝 **Report** — timestamped JSON + Markdown under `reports/`, plus a per-run
  logfile.

---

## Requirements

Assumed already installed and on `PATH` (standard on Kali rolling):

- Python 3.12+
- `nmap`, `searchsploit`
- Metasploit Framework (`msfconsole`, `msfrpcd`, `msfvenom`)

Python packages are listed in [`requirements.txt`](requirements.txt).

---

## Installation

```bash
git clone https://github.com/osmnabyram/ShellCracker.git
cd ShellCracker

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config.yaml.example config.yaml
```

The defaults work out of the box for a local lab — no editing required:

- `handler.lhost` defaults to `auto`; ShellCracker detects your attacking IP
  from the route to the target. Override it only if the wrong interface is
  picked.
- If `msfrpcd` is not already running, ShellCracker **starts it automatically**
  using the user/password/port in `config.yaml` (default `msf` / `msf` /
  `55553`) and shuts it back down afterwards (kept alive if a session landed).

> The UI is in Turkish; code, config and this README are in English.

---

## Usage

Just run it and enter the target when asked:

```bash
python3 shell.py
```

```text
  Sistem aciliyor      Hosgeldiniz

                 S H E L L C R A C K E R
            yalnizca yetkili lab kullanimi

[?] Kurban IP (tek adres): 192.168.56.101
    Hedef: 192.168.56.101
    LHOST: 192.168.56.1  (otomatik)

═══[ KESIF ]═══ ...
═══[ ESLESTIRME ]═══ ...
═══[ SOMURU ]═══ ...

  ╔══════════════════════════════════════╗
  ║  SHELL ALINDI  —  oturum 1 (shell)
  ╚══════════════════════════════════════╝
[*] Oturum yeni pencerede acildi (gnome-terminal). Komutlarini orada yaz.
```

On success the interactive shell opens in a **new terminal window** by
default, so you can type commands inside the session there while this window
finishes. Use `--ayni-pencere` to stay in the current window instead.

You can also pass the target non-interactively:

```bash
python3 shell.py --target 192.168.56.101
```

Options:

| Flag | Description |
| --- | --- |
| `--target <IP>` | Single target IP. CIDR/ranges/lists rejected. If omitted, you are prompted. |
| `--config <path>` | Config file (default `config.yaml`). |
| `--rapor` | Write JSON + Markdown report, logfile and raw nmap XML to `reports/` (off by default). |
| `--ayni-pencere` | Attach to the shell in THIS window instead of opening a new terminal (default is a new window). |

Exit codes: `0` success/clean no-op · `1` cancelled or error · `3` msfrpc
unreachable · `4` no shell obtained.

### Optional: start msfrpcd yourself

Auto-start covers the common case. If you prefer to run the daemon manually
(e.g. to watch its output), start it first and ShellCracker will reuse it:

```bash
msfrpcd -U msf -P msf -p 55553 -a 127.0.0.1
```

---

## Output

```
reports/
├── recon_<target>_<ts>.xml          # raw nmap XML
├── ShellCracker_<target>_<ts>.log     # full run log
├── ShellCracker_<target>_<ts>.json    # machine-readable record
└── ShellCracker_<target>_<ts>.md      # human-readable summary
```

---

## Roadmap

- Target validation against **Metasploitable 2** (vsftpd 2.3.4 backdoor,
  UnrealIRCd) planned — this section will be updated with real results once
  the first lab run is completed.

---

## License

[MIT](LICENSE). Provided as-is, for authorized security education and testing.
