"""External tool integration layer.

ShellCracker orchestrates already-installed security tools instead of
reimplementing them. This module is the single, dependency-free way the rest of
the code discovers, runs and times-out those CLI tools, so adding a new tool is
uniform and safe:

* :func:`have` checks whether a binary is on ``PATH``;
* :func:`run` executes an argument vector with a hard timeout and captures its
  output into a :class:`ToolResult`;
* a missing tool is **skipped with a note**, never a crash -- so ShellCracker
  keeps working on whatever subset of tools a given box actually has installed.

Like the rest of ShellCracker, every tool driven through here is pointed at the
single target address only. This module builds argument vectors and parses
output; it contains no target iteration of its own.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass

logger = logging.getLogger("ShellCracker.tools")


@dataclass
class ToolResult:
    """Outcome of one external-tool invocation."""

    tool: str
    available: bool = True      # was the binary found on PATH?
    ran: bool = False           # did the process actually start?
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        """True when the tool ran to completion without timeout or error."""
        return self.ran and not self.timed_out and not self.error

    @property
    def text(self) -> str:
        """stdout plus stderr -- many scanners print findings to stderr."""
        return (self.stdout or "") + (("\n" + self.stderr) if self.stderr else "")


def have(tool: str) -> bool:
    """Return True if ``tool`` is available on ``PATH``."""
    return shutil.which(tool) is not None


def available(tools: list[str]) -> list[str]:
    """Return the subset of ``tools`` that are installed."""
    return [t for t in tools if have(t)]


def run(
    argv: list[str],
    timeout: int = 180,
    input_text: str | None = None,
) -> ToolResult:
    """Run an external command and capture its result.

    Args:
        argv: Full argument vector; ``argv[0]`` is the binary. It is resolved
            against ``PATH`` first and the run is skipped (not failed) when the
            binary is missing.
        timeout: Hard wall-clock limit in seconds. On expiry the process is
            killed and ``timed_out`` is set (partial stdout is still returned).
        input_text: Optional text piped to the process's stdin.

    Returns:
        A :class:`ToolResult`. Never raises for the common failure modes
        (missing binary, timeout, spawn error) -- callers inspect ``.ok`` /
        ``.available`` instead.
    """
    tool = argv[0]
    if shutil.which(tool) is None:
        logger.info("  [atlandi] %s kurulu degil (PATH'te yok).", tool)
        return ToolResult(tool=tool, available=False, error="kurulu degil")

    logger.info("  calisiyor: %s", " ".join(argv))
    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return ToolResult(
            tool=tool, available=True, ran=True,
            returncode=proc.returncode,
            stdout=proc.stdout or "", stderr=proc.stderr or "",
            duration=time.time() - start,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        logger.warning("  %s %ds icinde bitmedi, durduruldu.", tool, timeout)
        return ToolResult(
            tool=tool, available=True, ran=True, timed_out=True,
            stdout=partial, error="timeout", duration=time.time() - start,
        )
    except Exception as exc:  # noqa: BLE001 - surface, never crash the pipeline
        logger.warning("  %s calistirilamadi: %s", tool, exc)
        return ToolResult(
            tool=tool, available=True, ran=False, error=str(exc),
            duration=time.time() - start,
        )
