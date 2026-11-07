"""Reconnaissance: service and version discovery with nmap.

Wraps python-nmap to run a service/version scan against a single target,
persists the raw XML output, and returns a normalised list of open services
that the matcher can consume.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import nmap

logger = logging.getLogger("shellforge.recon")


@dataclass
class Service:
    """A single open service discovered on the target."""

    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""

    @property
    def banner(self) -> str:
        """Human-readable service description (product + version + extra)."""
        parts = [p for p in (self.product, self.version, self.extrainfo) if p]
        return " ".join(parts) if parts else self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "cpe": self.cpe,
            "banner": self.banner,
        }


@dataclass
class ReconResult:
    """Outcome of a recon scan against one host."""

    target: str
    services: list[Service] = field(default_factory=list)
    raw_xml_path: str | None = None
    started_at: str = ""
    finished_at: str = ""

    def open_services(self) -> list[Service]:
        return [s for s in self.services if s.state == "open"]


def run_recon(
    target: str,
    nmap_arguments: str = "-sV -Pn",
    timeout: int = 300,
    reports_dir: str | Path = "reports",
    save_xml: bool = True,
) -> ReconResult:
    """Run an nmap service/version scan against ``target``.

    Args:
        target: A single resolved IPv4/IPv6 address (validated by the caller).
        nmap_arguments: Base nmap flags. ``-oX -`` is appended internally so
            python-nmap can parse XML regardless of what the caller passes.
        timeout: Per-scan timeout in seconds.
        reports_dir: Directory where the raw XML output is written.

    Returns:
        A :class:`ReconResult` with the parsed services and the XML path.

    Raises:
        nmap.PortScannerError: If nmap is missing from PATH or scanning fails.
    """
    scanner = nmap.PortScanner()
    started = datetime.now()
    logger.info("Keşif başlıyor: %s (parametre: %s)", target, nmap_arguments)

    # python-nmap already requests XML internally; we pass the service-scan
    # flags through the `arguments` parameter. -oX is handled by the library.
    scanner.scan(hosts=target, arguments=nmap_arguments, timeout=timeout)

    finished = datetime.now()
    result = ReconResult(
        target=target,
        started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"),
    )

    # Persist raw XML for auditability (only when requested, e.g. --rapor).
    if save_xml:
        reports_path = Path(reports_dir)
        reports_path.mkdir(parents=True, exist_ok=True)
        xml_file = reports_path / f"recon_{target.replace(':', '_')}_{started:%Y%m%d_%H%M%S}.xml"
        try:
            raw = scanner.get_nmap_last_output()
            if isinstance(raw, bytes):  # python-nmap version differences
                raw = raw.decode("utf-8", "replace")
            xml_file.write_text(raw)
            result.raw_xml_path = str(xml_file)
        except Exception as exc:  # noqa: BLE001 - XML dump is best-effort
            logger.warning("Ham nmap XML yazılamadı: %s", exc)

    if target not in scanner.all_hosts():
        logger.warning("Hedef %s sonuç döndürmedi (kapalı ya da filtreli).", target)
        return result

    host = scanner[target]
    for proto in host.all_protocols():
        for port in sorted(host[proto].keys()):
            info = host[proto][port]
            service = Service(
                port=int(port),
                protocol=proto,
                state=info.get("state", ""),
                name=info.get("name", ""),
                product=info.get("product", ""),
                version=info.get("version", ""),
                extrainfo=info.get("extrainfo", ""),
                cpe=info.get("cpe", ""),
            )
            result.services.append(service)
            logger.info(
                "  %s/%s %s  %s", port, proto, service.state, service.banner
            )

    logger.info(
        "Keşif bitti: %s üzerinde %d açık servis",
        target,
        len(result.open_services()),
    )
    return result
