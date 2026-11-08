"""NSE vulnerability scanning: turn nmap's vuln scripts into exploit vectors.

The service/version scan in :mod:`core.recon` tells us *what* is running; this
module runs nmap's vulnerability scripts (``--script vuln,vulners``) to find out
*what is exploitable*, and turns every confirmed finding into a
:class:`~core.strategy.Finding` that feeds straight back into the engine:

* a ``smb-vuln-ms17-010`` hit  -> ``smb.ms17_010`` finding -> EternalBlue injected;
* any ``*-vuln-*`` script that reports **VULNERABLE** with a CVE, and every CVE
  the ``vulners`` script maps to a known RCE module (see ``_CVE_EXPLOITS``), ->
  a ``cve`` finding -> the exact Metasploit module injected at a high score.

So a single nmap pass becomes ready-to-fire exploits -- the shortest path from
"port is open" to "session". Everything here points at the single target only;
nmap is driven through :mod:`core.tools`, so a missing binary or a timeout is a
skipped step, never a crash. CVEs that have no reliable module are still kept as
informational facts for the report.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

from . import tools
from .recon import Service
from .strategy import _CVE_EXPLOITS, Finding

logger = logging.getLogger("ShellCracker.nse")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# "VULNERABLE" but not "NOT VULNERABLE" (fixed-width lookbehind).
_VULN_RE = re.compile(r"(?<!NOT )VULNERABLE")

# NSE script id (substring) -> a dedicated finding the engine already handles.
_SCRIPT_FINDINGS: list[tuple[str, str, int]] = [
    ("smb-vuln-ms17-010", "smb.ms17_010", 445),
    ("smb-double-pulsar", "smb.ms17_010", 445),
]


def _script_is_vulnerable(output: str) -> bool:
    """True when a vuln-category script's output confirms a vulnerability."""
    up = output.upper()
    if "NOT VULNERABLE" in up and "VULNERABLE" not in _VULN_RE.sub("", up):
        return False
    return bool(_VULN_RE.search(up)) or "LIKELY VULNERABLE" in up


def parse_nmap_vuln_xml(xml_text: str) -> list[Finding]:
    """Parse nmap ``-oX`` output with script results into findings.

    Pure function (no I/O) so it is unit-testable. Emits:
      * dedicated findings for mapped scripts (ms17-010 -> ``smb.ms17_010``);
      * ``cve`` findings for CVEs confirmed VULNERABLE by a ``*-vuln-*`` script,
        and for any CVE the ``vulners`` script maps that we have a module for;
      * a single ``nse.cves`` fact listing every CVE seen (for the report).
    """
    findings: list[Finding] = []
    seen_cves: set[str] = set()
    all_cves: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("NSE XML ayristirilamadi: %s", exc)
        return findings

    host = root.find("host")
    if host is None:
        return findings

    # Gather (script_id, output, port) from both port-level and host-level scripts.
    script_hits: list[tuple[str, str, int]] = []
    for port_el in host.iterfind("./ports/port"):
        try:
            port = int(port_el.get("portid", "0"))
        except (TypeError, ValueError):
            port = 0
        for scr in port_el.iterfind("script"):
            script_hits.append(
                (scr.get("id", ""), scr.get("output", "") or "", port))
    for scr in host.iterfind("./hostscript/script"):
        script_hits.append((scr.get("id", ""), scr.get("output", "") or "", 0))

    for sid, output, port in script_hits:
        sid_l = sid.lower()

        # 1) Dedicated script -> known finding key (ms17-010 etc.).
        for needle, key, default_port in _SCRIPT_FINDINGS:
            if needle in sid_l and _script_is_vulnerable(output):
                findings.append(Finding(
                    key=key, value=True, port=port or default_port,
                    category="smb", detail=f"NSE {sid}: ZAFIYETLI"))

        is_vuln_script = "vuln" in sid_l and sid_l != "vulners"
        is_vulners = sid_l == "vulners"
        cves = {c.upper() for c in _CVE_RE.findall(output)}
        for cve in sorted(cves):
            if cve not in seen_cves:
                seen_cves.add(cve)
                all_cves.append(cve)

        # 2) CVE findings. A *-vuln-* script that says VULNERABLE confirms its
        #    CVEs; vulners is version-inference, so only trust its CVEs when we
        #    have a curated module for them (avoids injecting noise).
        confirmed = is_vuln_script and _script_is_vulnerable(output)
        for cve in sorted(cves):
            actionable = cve in _CVE_EXPLOITS
            if confirmed or (is_vulners and actionable):
                tag = "ZAFIYETLI" if confirmed else "vulners eslesmesi"
                findings.append(Finding(
                    key="cve", value=cve, port=port, category="",
                    detail=f"NSE {sid}: {cve} ({tag})"))

    if all_cves:
        findings.append(Finding(
            key="nse.cves", value=all_cves, port=0, category="",
            detail=f"NSE {len(all_cves)} CVE gordu: " + ", ".join(all_cves[:15])))
    return findings


class NseScanner:
    """Runs nmap's vulnerability scripts against one target's open ports."""

    def __init__(self, target: str, config: dict) -> None:
        self.target = target
        cfg = (config or {}).get("nse", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.scripts = str(cfg.get("scripts", "vuln,vulners"))
        self.timeout = int(cfg.get("timeout", 600))
        self.extra_args = str(cfg.get("extra_args", "")).split()

    def tool_status(self) -> bool:
        """Whether nmap is installed."""
        return tools.have("nmap")

    def scan(self, services: list[Service]) -> list[Finding]:
        """Run the NSE vuln scan against the discovered open ports."""
        if not self.enabled:
            logger.info("NSE kapali (nse.enabled=false).")
            return []
        if not tools.have("nmap"):
            logger.info("  [atlandi] nmap kurulu degil.")
            return []

        ports = sorted({s.port for s in services if s.port})
        argv = ["nmap", "-sV", "-Pn", "--script", self.scripts]
        if ports:
            argv += ["-p", ",".join(str(p) for p in ports)]
        if self.extra_args:
            argv += self.extra_args
        argv += ["-oX", "-", self.target]

        logger.info("NSE zafiyet taramasi: --script %s (%d port)",
                    self.scripts, len(ports))
        res = tools.run(argv, timeout=self.timeout)
        if not res.stdout:
            if res.timed_out:
                logger.info("  NSE zaman asimina ugradi, kismi sonuc yok.")
            return []
        findings = parse_nmap_vuln_xml(res.stdout)
        logger.info("  NSE: %d bulgu.", len(findings))
        return findings
