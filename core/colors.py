"""Dependency-free ANSI colouring/styling for user-facing output.

Styles are only emitted when writing to a real terminal and ``NO_COLOR`` is
unset, so piped/redirected output and logfiles stay clean. Palette (bright
variants read well on Kali's dark terminal):

    info -> blue   ok -> green   err -> red   warn -> yellow   dim -> grey
    plus: bold, cyan, magenta, white, red, green, yellow, blue
"""

from __future__ import annotations

import os
import sys

# Style/colour name -> ANSI SGR code. Several may be combined via ``style``.
_CODES = {
    "bold": "1",
    "dim": "90",
    "info": "94",     # bright blue
    "ok": "92",       # bright green
    "err": "91",      # bright red
    "warn": "93",     # bright yellow
    "cyan": "96",
    "magenta": "95",
    "white": "97",
    "red": "91",
    "green": "92",
    "yellow": "93",
    "blue": "94",
}


def use_color(stream=None) -> bool:
    """Return True if styling should be emitted for ``stream`` (default stdout)."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - some streams lack isatty
        return False


def style(text: str, *kinds: str, enabled: bool | None = None) -> str:
    """Wrap ``text`` in one or more ANSI styles, e.g. ``style(x, "bold", "ok")``."""
    on = use_color() if enabled is None else enabled
    codes = [_CODES[k] for k in kinds if k in _CODES]
    if not on or not codes:
        return text
    return "\033[" + ";".join(codes) + "m" + text + "\033[0m"


def info(text: str) -> str:
    return style(text, "info")


def ok(text: str) -> str:
    return style(text, "ok")


def err(text: str) -> str:
    return style(text, "err")


def warn(text: str) -> str:
    return style(text, "warn")


def dim(text: str) -> str:
    return style(text, "dim")


def bold(text: str) -> str:
    return style(text, "bold")
