#!/usr/bin/env python3
"""Standalone session attach for shellforge's --pencere flag.

Connects to a running msfrpcd and hands the terminal to an existing session by
ID. shellforge launches this in a new gnome-terminal window; it can also be run
manually to re-attach to a session later.

Example:
    python3 attach.py --sid 1 --host 127.0.0.1 --port 55553 \
        --user msf --password msf
"""

from __future__ import annotations

import argparse
import sys

from core import executor as execmod
from core.colors import err
from core.interactive import interactive_loop


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attach",
        description="Attach to an existing Metasploit session over msfrpc.",
    )
    parser.add_argument("--sid", type=int, required=True, help="Session ID to attach to.")
    parser.add_argument("--host", default="127.0.0.1", help="msfrpcd host.")
    parser.add_argument("--port", type=int, default=55553, help="msfrpcd port.")
    parser.add_argument("--user", default="msf", help="msfrpcd user.")
    parser.add_argument("--password", default="msf", help="msfrpcd password.")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL.")
    args = parser.parse_args(argv)

    try:
        client = execmod.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            ssl=not args.no_ssl,
        )
    except execmod.MsfConnectionError as exc:
        print(err(f"[!] {exc}"))
        input("\nKapatmak için Enter'a bas...")  # keep the new window open to read the error
        return 3

    interactive_loop(client, args.sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
