"""SMB / Active Directory enumeration via netexec (formerly crackmapexec).

For Windows and AD targets the SMB service is usually the shortest path to a
shell, and netexec is the sharpest knife for it. This module drives it against
the single target and turns what it learns into
:class:`~core.strategy.Finding` objects the engine already knows how to use:

* **host fingerprint** (signing, SMBv1, domain/hostname) -> facts + a hint note;
  an exposed SMBv1 is exactly what the NSE/MSF MS17-010 checks confirm next;
* **null-session shares** -> ``smb.null_session`` + a readable-shares note;
* **RID-brute / user enumeration** -> a ``smb.users`` finding, whose names are
  fed into every login module so the brute/credential phases try real accounts;
* **a valid or ``Pwn3d!`` credential** (anonymous/guest) -> a ``creds`` finding,
  which the engine reuses across services and which unlocks psexec -> a shell.

netexec is optional (``nxc`` / ``netexec`` / ``crackmapexec`` / ``cme`` are each
tried in turn); if none is installed the step is skipped with a note. Only the
single target is ever contacted, and only anonymous/guest access is probed here
-- no password spraying, that stays in the dedicated credential phases.
"""

from __future__ import annotations

import logging
import re

from . import tools
from .recon import Service
from .strategy import Finding

logger = logging.getLogger("ShellCracker.smbenum")

_BINARIES = ("nxc", "netexec", "crackmapexec", "cme")
_SMB_NAMES = ("microsoft-ds", "netbios-ssn", "smb")
_SMB_PORTS = (445, 139)

# Strip the leading "SMB  <ip>  <port>  <host>  " prefix netexec prints.
_PREFIX_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+", re.M)


def smb_binary() -> str | None:
    """Return the first installed netexec/crackmapexec binary, or None."""
    for b in _BINARIES:
        if tools.have(b):
            return b
    return None


def parse_host_info(text: str) -> dict:
    """Extract signing / SMBv1 / domain / hostname / OS from the banner line."""
    info: dict = {}
    m = re.search(r"\(name:([^)]*)\)", text)
    if m:
        info["hostname"] = m.group(1).strip()
    m = re.search(r"\(domain:([^)]*)\)", text)
    if m:
        info["domain"] = m.group(1).strip()
    m = re.search(r"\(signing:(True|False)\)", text, re.I)
    if m:
        info["signing"] = m.group(1).lower() == "true"
    m = re.search(r"\(SMBv1:(True|False)\)", text, re.I)
    if m:
        info["smbv1"] = m.group(1).lower() == "true"
    m = re.search(r"\[\*\]\s+(Windows[^(]*)\(name:", text)
    if m:
        info["os"] = m.group(1).strip()
    return info


def parse_creds(text: str) -> list[tuple[str, str, bool]]:
    """Return (user, password, pwned) for each successful login line.

    netexec prints ``[+] DOMAIN\\user:password`` on success and appends
    ``(Pwn3d!)`` when that account can execute code (admin) -- a guaranteed
    psexec shell.
    """
    out: list[tuple[str, str, bool]] = []
    for m in re.finditer(
        r"\[\+\]\s+(?:[^\\\s]+\\)?([^\s:]+):(\S*?)\s*(\(Pwn3d!\))?\s*$",
        text, re.M,
    ):
        user = m.group(1)
        pw = m.group(2) or ""
        pwned = bool(m.group(3))
        pair = (user, pw, pwned)
        if pair not in out:
            out.append(pair)
    return out


def parse_shares(text: str) -> list[tuple[str, str]]:
    """Parse ``(share_name, permissions)`` rows from ``--shares`` output."""
    shares: list[tuple[str, str]] = []
    body = _PREFIX_RE.sub("", text)
    for line in body.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("share") or set(line) <= {"-", " "}:
            continue
        parts = re.split(r"\s{2,}", line)
        name = parts[0].strip()
        # The 2nd column is Permissions only when it reads like one (READ /
        # WRITE); otherwise it is the Remark column (empty permissions) and is
        # dropped, so a share with no access is not mislabelled as readable.
        perms = parts[1].strip() if len(parts) > 1 else ""
        if not re.fullmatch(r"(READ|WRITE)(,(READ|WRITE))*", perms, re.I):
            perms = ""
        if name and re.match(r"^[\w$.\-]+$", name):
            shares.append((name, perms))
    return shares


def parse_rid_users(text: str) -> list[str]:
    """Parse usernames from ``--rid-brute`` / ``--users`` output.

    Machine accounts (trailing ``$``) are dropped -- they are not login targets.
    """
    users: list[str] = []
    for m in re.finditer(r"\\([^\\\s]+)\s*\(SidType(?:User)\)", text):
        u = m.group(1).strip()
        if u and not u.endswith("$") and u not in users:
            users.append(u)
    # --users table form: "DOMAIN\user   badpwdcount: ..."
    for m in re.finditer(r"\\([^\\\s]+)\s+badpwdcount", text, re.I):
        u = m.group(1).strip()
        if u and not u.endswith("$") and u not in users:
            users.append(u)
    return users


class SmbEnumRunner:
    """Runs netexec against one target's SMB service and emits findings."""

    def __init__(self, target: str, config: dict) -> None:
        self.target = target
        cfg = (config or {}).get("smbenum", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.do_shares = bool(cfg.get("shares", True))
        self.do_rid_brute = bool(cfg.get("rid_brute", True))
        self.timeout = int(cfg.get("timeout", 300))
        self.binary = smb_binary()

    def tool_status(self) -> bool:
        return self.binary is not None

    @staticmethod
    def _is_smb(svc: Service) -> bool:
        name = (svc.name or "").lower()
        return svc.port in _SMB_PORTS or any(n in name for n in _SMB_NAMES)

    def _run(self, *args: str) -> str:
        argv = [self.binary, "smb", self.target, *args]
        res = tools.run(argv, timeout=self.timeout)
        return res.text if (res.stdout or res.stderr) else ""

    def scan(self, services: list[Service]) -> list[Finding]:
        """Enumerate the SMB service anonymously; return findings for the engine."""
        if not self.enabled:
            logger.info("smbenum kapali (smbenum.enabled=false).")
            return []
        if not self.binary:
            logger.info("  [atlandi] netexec/crackmapexec kurulu degil.")
            return []
        smb_svcs = [s for s in services if self._is_smb(s)]
        if not smb_svcs:
            logger.info("smbenum: SMB servisi yok, atlaniyor.")
            return []

        logger.info("SMB/AD keşfi (%s): %s", self.binary, self.target)
        findings: list[Finding] = []

        # 1) Host fingerprint (signing / SMBv1 / domain).
        info = parse_host_info(self._run())
        if info:
            if "signing" in info:
                findings.append(Finding(
                    key="smb.signing", value=info["signing"], port=445,
                    category="smb",
                    detail=f"SMB imzalama: {'acik' if info['signing'] else 'KAPALI'}"))
            if info.get("smbv1"):
                findings.append(Finding(
                    key="smb.smbv1", value=True, port=445, category="smb",
                    detail="SMBv1 ACIK -> MS17-010 adayi (NSE/MSF dogrulayacak)"))
            if info.get("domain"):
                findings.append(Finding(
                    key="smb.domain", value=info["domain"], port=445,
                    category="smb", detail=f"Domain/workgroup: {info['domain']}"))

        # 2) Null-session shares.
        if self.do_shares:
            share_out = self._run("-u", "", "-p", "", "--shares")
            for user, pw, pwned in parse_creds(share_out):
                findings.append(Finding(
                    key="creds", value=(user, pw), port=445, category="smb",
                    detail=f"netexec: smb {user}:{pw or '<bos>'}"
                           + (" (Pwn3d! -> psexec)" if pwned else "")))
            shares = parse_shares(share_out)
            if shares:
                findings.append(Finding(key="smb.null_session", value=True,
                                        port=445, category="smb",
                                        detail="Null-session ile share listelendi"))
                findings.append(Finding(
                    key="smb.shares",
                    value=[f"{n}({p})" if p else n for n, p in shares],
                    port=445, category="smb",
                    detail="SMB paylasimlari: "
                           + ", ".join(f"{n}:{p or '-'}" for n, p in shares[:12])))

        # 3) User enumeration (RID brute).
        if self.do_rid_brute:
            rid_out = self._run("-u", "", "-p", "", "--rid-brute")
            users = parse_rid_users(rid_out)
            if users:
                findings.append(Finding(
                    key="smb.users", value=users, port=445, category="smb",
                    detail=f"{len(users)} kullanici: " + ", ".join(users[:15])))

        logger.info("  SMB/AD keşfi: %d bulgu.", len(findings))
        return findings
