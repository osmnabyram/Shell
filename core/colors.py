"""Dependency-free ANSI colouring for user-facing output.

Colours are only emitted when writing to a real terminal and the ``NO_COLOR``
environment variable is unset, so piped/redirected output and logfiles stay
clean. Palette (Kali dark-terminal friendly, bright variants):

    info  -> blue      ok -> green      err -> red      warn -> yellow
"""

from __future__ import annotations

import os
import sys

# Semantic name -> ANSI SGR code (bright variants read well on dark terminals).
_CODES = {
    "info": "94",   # bright blue
    "ok": "92",     # bright green
    "err": "91",    # bright red
    "warn": "93",   # bright yellow
    "dim": "90",    # grey
}


def use_color(stream=None) -> bool:
    """Return True if colour should be emitted for ``stream`` (default stdout)."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - some streams lack isatty
        return False


def paint(kind: str, text: str, *, enabled: bool | None = None) -> str:
    """Wrap ``text`` in the ANSI code for ``kind`` when colour is enabled."""
    on = use_color() if enabled is None else enabled
    code = _CODES.get(kind)
    if not on or not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def info(text: str) -> str:
    return paint("info", text)


def ok(text: str) -> str:
    return paint("ok", text)


def err(text: str) -> str:
    return paint("err", text)


def warn(text: str) -> str:
    return paint("warn", text)


def dim(text: str) -> str:
    return paint("dim", text)
