# shellforge

> Autonomous, single-target exploitation pipeline for **authorized lab use only**.

shellforge chains reconnaissance, exploit matching, validation and firing into
one CLI run. Given a single target IP, it scans with nmap, matches discovered
services against the Metasploit module database (and Exploit-DB for reference),
validates candidates, fires them through a reverse handler until a session
lands, verifies the session, and writes a full report.

It is a thin orchestration layer over tools that already ship with Kali Linux
(`nmap`, `searchsploit`, Metasploit via `msfrpcd`). It does **not** contain or
develop exploit code of its own.

---

## ⚠️ Authorized lab use only

shellforge is built for **your own virtual machines and sanctioned training
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
  sessions shellforge itself opened.

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
git clone https://github.com/<you>/shellforge.git
cd shellforge

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config.yaml.example config.yaml
```

The defaults work out of the box for a local lab — no editing required:

- `handler.lhost` defaults to `auto`; shellforge detects your attacking IP
  from the route to the target. Override it only if the wrong interface is
  picked.
- If `msfrpcd` is not already running, shellforge **starts it automatically**
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
[?] Kurban IP (tek adres): 192.168.56.101
[?] 192.168.56.101 sana ait VEYA test için YAZILI iznin olan bir lab mı? [e/H] e
[*] LHOST otomatik belirlendi: 192.168.56.1
[*] Metasploit RPC'ye bağlanılıyor (çalışmıyorsa otomatik başlatılır)...
...
[+] SHELL ALINDI! Oturum detayları ve kanıt için rapora bak.
```

You can also pass the target non-interactively:

```bash
python3 shell.py --target 192.168.56.101
```

Options:

| Flag | Description |
| --- | --- |
| `--target <IP>` | Single target IP. CIDR/ranges/lists rejected. If omitted, you are prompted. |
| `--config <path>` | Config file (default `config.yaml`). |
| `--yes` | Pre-confirm the authorization prompt for unattended lab runs (still logged). |

Exit codes: `0` success/clean no-op · `1` cancelled or error · `3` msfrpc
unreachable · `4` no shell obtained.

### Optional: start msfrpcd yourself

Auto-start covers the common case. If you prefer to run the daemon manually
(e.g. to watch its output), start it first and shellforge will reuse it:

```bash
msfrpcd -U msf -P msf -p 55553 -a 127.0.0.1
```

---

## Output

```
reports/
├── recon_<target>_<ts>.xml          # raw nmap XML
├── shellforge_<target>_<ts>.log     # full run log
├── shellforge_<target>_<ts>.json    # machine-readable record
└── shellforge_<target>_<ts>.md      # human-readable summary
```

---

## Roadmap

- Target validation against **Metasploitable 2** (vsftpd 2.3.4 backdoor,
  UnrealIRCd) planned — this section will be updated with real results once
  the first lab run is completed.

---

## License

[MIT](LICENSE). Provided as-is, for authorized security education and testing.
