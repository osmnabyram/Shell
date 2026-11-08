"""Dependency doctor: see what ShellCracker can use, and install what it cannot.

A fresh clone only works as well as the tools installed on the box, and a user
should not have to read the README to find out which of a dozen optional CLIs
they are missing. This module is the single place that:

* knows every external tool ShellCracker can drive, its package name, and
  whether it is core (nothing runs without it) or optional (a phase is skipped);
* reports what is present and what is missing (``--check``);
* installs the missing ones via the system package manager (``--kur``).

Installing changes the system, so it only ever runs on an explicit ``--kur``,
only through ``apt`` (Kali/Debian/Ubuntu), and asks for confirmation unless
``-y`` is given. On any other distro it prints the package list and stops --
it never guesses a package manager or pipes a remote script into a shell.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import shutil
import sys
from dataclasses import dataclass

from . import colors as C
from . import tools

logger = logging.getLogger("ShellCracker.doctor")


@dataclass
class Tool:
    """One external dependency ShellCracker can use."""

    name: str                       # display name
    binaries: list[str]             # present if ANY of these is on PATH
    package: str                    # apt package that provides it
    group: str                      # core | vulnscan | bruteforce | hashcrack
    required: bool = False          # core tools: nothing runs without them
    note: str = ""                  # shown in the report / install hint

    def present(self) -> bool:
        return any(shutil.which(b) for b in self.binaries)

    def found_binary(self) -> str:
        for b in self.binaries:
            if shutil.which(b):
                return b
        return ""


# The full dependency catalogue. Order groups core-first, then by phase.
TOOLS: list[Tool] = [
    # --- core: the pipeline cannot run without these -----------------------
    Tool("nmap", ["nmap"], "nmap", "core", required=True,
         note="port/servis taramasi ve NSE zafiyet scriptleri"),
    Tool("Metasploit", ["msfconsole", "msfrpcd"], "metasploit-framework",
         "core", required=True, note="exploit/oturum motoru (msfrpc)"),
    Tool("searchsploit", ["searchsploit"], "exploitdb", "core",
         note="Exploit-DB eslesmeleri (rapor icin)"),
    # --- vulnscan phase ----------------------------------------------------
    Tool("netexec", ["nxc", "netexec", "crackmapexec", "cme"], "netexec",
         "vulnscan", note="SMB/AD enum (share/kullanici/Pwn3d)"),
    Tool("nuclei", ["nuclei"], "nuclei", "vulnscan",
         note="sablon tabanli CVE/exposure taramasi"),
    Tool("whatweb", ["whatweb"], "whatweb", "vulnscan",
         note="web teknoloji/urun parmak izi"),
    Tool("gobuster", ["gobuster"], "gobuster", "vulnscan",
         note="gizli dizin/dosya kesfi"),
    Tool("ffuf", ["ffuf"], "ffuf", "vulnscan",
         note="dizin kesfi (gobuster alternatifi)"),
    Tool("nikto", ["nikto"], "nikto", "vulnscan",
         note="klasik web sunucu taramasi (opsiyonel)"),
    # --- bruteforce phase --------------------------------------------------
    Tool("hydra", ["hydra"], "hydra", "bruteforce",
         note="wordlist kimlik saldirisi"),
    # --- offline hash cracking ---------------------------------------------
    Tool("john", ["john"], "john", "hashcrack",
         note="looted hash kirma"),
    Tool("hashcat", ["hashcat"], "hashcat", "hashcrack",
         note="GPU hash kirma (john alternatifi)"),
    Tool("wordlists", ["__rockyou__"], "wordlists", "hashcrack",
         note="rockyou.txt vb. (brute/crack icin)"),
]

# Python packages from requirements.txt (checked by import name).
_PY_MODULES = {"nmap": "python-nmap", "pymetasploit3": "pymetasploit3",
               "yaml": "PyYAML"}

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"


def _rockyou_present() -> bool:
    return os.path.exists(_ROCKYOU) or os.path.exists(_ROCKYOU + ".gz")


def _tool_present(t: Tool) -> bool:
    if t.binaries == ["__rockyou__"]:
        return _rockyou_present()
    return t.present()


def missing_python() -> list[str]:
    """Return the pip package names for any importable deps that are missing."""
    out: list[str] = []
    for mod, pkg in _PY_MODULES.items():
        if mod in sys.modules:
            continue
        try:
            spec = importlib.util.find_spec(mod)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            out.append(pkg)
    return out


def missing_tools(required_only: bool = False) -> list[Tool]:
    """Return the Tool entries whose binary/file is not present."""
    out = [t for t in TOOLS if not _tool_present(t)]
    if required_only:
        out = [t for t in out if t.required]
    return out


def have_apt() -> bool:
    """Whether this box has apt-get (Kali/Debian/Ubuntu)."""
    return shutil.which("apt-get") is not None


def report() -> int:
    """Print a present/missing table. Return count of missing tools."""
    groups = ["core", "vulnscan", "bruteforce", "hashcrack"]
    labels = {"core": "CEKIRDEK (zorunlu)", "vulnscan": "VULNSCAN",
              "bruteforce": "BRUTEFORCE", "hashcrack": "HASH KIRMA"}
    print(C.bold("\n  ShellCracker bagimlilik kontrolu\n"))
    missing_req = 0
    for g in groups:
        print(C.bold(f"  {labels[g]}"))
        for t in [t for t in TOOLS if t.group == g]:
            ok = _tool_present(t)
            mark = C.ok("  [VAR]  ") if ok else C.err("  [YOK]  ")
            extra = ""
            if ok and t.binaries != ["__rockyou__"]:
                fb = t.found_binary()
                extra = C.dim(f"  ({fb})") if fb and fb != t.name else ""
            print(f"  {mark}{t.name:<14}{extra}  " + C.dim(t.note))
            if not ok and t.required:
                missing_req += 1
        print()

    py = missing_python()
    if py:
        print(C.err("  [YOK]  ") + "Python paketleri: " + ", ".join(py)
              + C.dim("  -> pip install -r requirements.txt"))
    else:
        print(C.ok("  [VAR]  ") + "Python paketleri (python-nmap, pymetasploit3, PyYAML)")

    miss = missing_tools()
    print()
    if not miss and not py:
        print(C.ok("  Her sey kurulu. Hazirsin."))
    else:
        total = len(miss) + (1 if py else 0)
        print(C.warn(f"  {total} eksik var.") + C.dim("  Kurmak icin: python shell.py --kur"))
        if missing_req:
            print(C.err(f"  DIKKAT: {missing_req} CEKIRDEK arac eksik; onlarsiz tool calismaz."))
    return len(miss)


def install_missing(assume_yes: bool = False) -> int:
    """Install the missing tools via apt (and pip for Python deps).

    Returns a process-style exit code (0 = nothing to do / success).
    """
    miss = missing_tools()
    py = missing_python()
    if not miss and not py:
        print(C.ok("  Eksik yok, kurulacak bir sey yok."))
        return 0

    if miss and not have_apt():
        print(C.err("  apt bulunamadi (Kali/Debian/Ubuntu degil?)."))
        print("  Su paketleri elle kur: "
              + ", ".join(sorted({t.package for t in miss})))
        return 2

    packages = sorted({t.package for t in miss})
    if packages:
        print(C.bold("\n  Kurulacak paketler: ") + ", ".join(packages))
    if py:
        print(C.bold("  Kurulacak Python paketleri: ") + ", ".join(py))

    if not assume_yes:
        try:
            ans = input(C.warn("\n  Devam edilsin mi? [e/H] ")).strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("e", "evet", "y", "yes"):
            print(C.dim("  Iptal edildi."))
            return 1

    rc = 0
    if packages:
        sudo = [] if os.geteuid() == 0 else ["sudo"]  # type: ignore[attr-defined]
        print(C.dim("\n  apt-get update ..."))
        tools.run(sudo + ["apt-get", "update"], timeout=600)
        print(C.dim("  apt-get install ..."))
        res = tools.run(sudo + ["apt-get", "install", "-y", *packages], timeout=1800)
        if res.stdout:
            print(res.stdout[-2000:])
        if not res.ok or (res.returncode not in (0, None)):
            print(C.err("  apt kurulumunda sorun olabilir, ciktiyi kontrol et."))
            rc = 3
        # netexec is 'crackmapexec' on older Kali; hint the pipx fallback.
        if any(t.package == "netexec" for t in miss) and not _tool_present(
                next(t for t in TOOLS if t.name == "netexec")):
            print(C.dim("  netexec apt'te yoksa: pipx install "
                        "git+https://github.com/Pennyw0rth/NetExec"))

    if py:
        print(C.dim("  pip install -r requirements.txt ..."))
        res = tools.run(["pip", "install", "-r", "requirements.txt"], timeout=600)
        if not res.ok:
            tools.run(["pip3", "install", "-r", "requirements.txt"], timeout=600)

    print()
    report()
    return rc
