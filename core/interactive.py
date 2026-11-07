"""Interactive bridge to a live Metasploit session over msfrpc.

Provides a simple read/eval/print loop that forwards the user's typed commands
to a shell or meterpreter session and prints the output back, until the user
types ``exit`` (or sends EOF). Works both in-process (ShellCracker's default) and
standalone (``attach.py`` launched in a separate terminal window).
"""

from __future__ import annotations

import time
from typing import Any

from .colors import dim, err, info, ok, warn


def _session_type(client: Any, sid: int) -> str:
    """Return the session's type string ('shell' / 'meterpreter') if known."""
    try:
        listing = client.sessions.list
        meta = listing.get(str(sid)) or listing.get(sid) or {}
        return meta.get("type", "")
    except Exception:  # noqa: BLE001
        return ""


def _drain(session: Any, tries: int = 12, delay: float = 0.3) -> str:
    """Read from a session until it stops producing output (best-effort)."""
    out = ""
    for _ in range(tries):
        time.sleep(delay)
        try:
            chunk = session.read()
        except Exception:  # noqa: BLE001 - read may transiently fail
            break
        if chunk:
            out += chunk
        elif out:
            break
    return out


def interactive_loop(client: Any, sid: int) -> None:
    """Hand the terminal to session ``sid`` until the user exits.

    The session is never killed here; it stays alive on the framework so it can
    be reused afterwards.
    """
    stype = _session_type(client, sid)
    try:
        session = client.sessions.session(sid)
    except Exception as exc:  # noqa: BLE001
        print(err(f"[!] Oturum {sid} alinamadi: {exc}"))
        return

    print(ok(f"\n[+] Oturum {sid} ({stype or '?'}) acildi — interaktif moda geciliyor."))
    print(dim("    Cikmak icin 'exit' / 'cikis' ya da Ctrl+D. Oturum arkada canli kalir."))

    is_meterpreter = stype == "meterpreter"

    # Print any banner/output already waiting on a shell session.
    if not is_meterpreter:
        initial = _drain(session, tries=4)
        if initial:
            print(initial, end="" if initial.endswith("\n") else "\n")

    prompt = info(f"{stype or 'shell'}@{sid}> ")
    while True:
        try:
            cmd = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        stripped = cmd.strip()
        if stripped in ("exit", "quit", "cikis", "cikis"):
            break
        if not stripped:
            continue
        try:
            if is_meterpreter:
                session.write(cmd)
            else:
                session.write(cmd + "\n")
            out = _drain(session)
            if out:
                print(out, end="" if out.endswith("\n") else "\n")
        except Exception as exc:  # noqa: BLE001 - keep the loop alive on errors
            print(err(f"[!] Komut hatasi: {exc}"))

    print(warn("[*] Interaktif moddan cikildi (oturum canli birakildi)."))
