"""Exploit matching: map discovered services to candidate exploits.

Two independent sources are consulted for each service:

* **searchsploit** (Exploit-DB) via its CLI ``--json`` output. These results
  are informational only -- they are recorded in the report but cannot be
  auto-fired, because an Exploit-DB entry is not necessarily a Metasploit
  module.
* **Metasploit module database** via msfrpc (``client.modules.search``). These
  results are actionable: each corresponds to a module the executor can load.

The matcher never runs anything against the target; it only queries local
databases to build a ranked candidate list.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable

from .recon import Service

logger = logging.getLogger("ShellCracker.matcher")

# Metasploit exploit ranks ordered from most to least reliable. Used to sort
# candidates so the executor tries the safest, highest-probability ones first.
_RANK_ORDER = {
    "excellent": 6,
    "great": 5,
    "good": 4,
    "normal": 3,
    "average": 2,
    "low": 1,
    "manual": 0,
}


@dataclass
class ExploitCandidate:
    """A single actionable Metasploit exploit candidate for a service."""

    module: str                      # e.g. "unix/ftp/vsftpd_234_backdoor"
    title: str
    rank: str
    service_port: int
    service_name: str
    disclosure_date: str = ""

    @property
    def rank_score(self) -> int:
        return _RANK_ORDER.get(self.rank.lower(), 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "rank": self.rank,
            "service_port": self.service_port,
            "service_name": self.service_name,
            "disclosure_date": self.disclosure_date,
        }


@dataclass
class ServiceMatches:
    """All matches found for one service."""

    service: Service
    msf_candidates: list[ExploitCandidate] = field(default_factory=list)
    searchsploit_hits: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service.to_dict(),
            "msf_candidates": [c.to_dict() for c in self.msf_candidates],
            "searchsploit_hits": self.searchsploit_hits,
        }


def _search_terms(service: Service) -> list[str]:
    """Build de-duplicated search terms from a service's fingerprint."""
    terms: list[str] = []
    for value in (service.product, service.name):
        value = (value or "").strip()
        if not value:
            continue
        if service.version:
            terms.append(f"{value} {service.version}".strip())
        terms.append(value)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for t in terms:
        key = t.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(t)
    return out


def _run_searchsploit(term: str) -> list[dict[str, Any]]:
    """Query searchsploit for ``term`` and return its JSON result list."""
    if not shutil.which("searchsploit"):
        logger.warning("searchsploit PATH'te bulunamadı; Exploit-DB sorgusu atlanıyor.")
        return []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", term],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("searchsploit %r için başarısız: %s", term, exc)
        return []

    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.debug("searchsploit returned non-JSON output for %r", term)
        return []
    return data.get("RESULTS_EXPLOIT", []) or []


def _search_msf(client: Any, term: str) -> list[dict[str, Any]]:
    """Search the Metasploit module DB for exploit modules matching ``term``.

    Returns the raw result dicts from pymetasploit3's ``modules.search``.
    Connection/search errors are logged and swallowed so one bad term does
    not abort the whole matching pass.
    """
    if client is None:
        return []
    try:
        results = client.modules.search(term)
    except Exception as exc:  # noqa: BLE001 - msfrpc errors are non-fatal here
        logger.warning("msf modül araması %r için başarısız: %s", term, exc)
        return []
    # Keep only exploit modules; payloads/aux/post are not directly fireable here.
    return [r for r in results if r.get("type") == "exploit"]


def match_services(
    services: Iterable[Service],
    msf_client: Any = None,
    use_searchsploit: bool = True,
) -> list[ServiceMatches]:
    """Build candidate exploit lists for each open service.

    Args:
        services: Open services from recon.
        msf_client: A connected pymetasploit3 ``MsfRpcClient`` (or ``None`` to
            skip Metasploit matching, e.g. during offline testing).
        use_searchsploit: Whether to also query Exploit-DB for the report.

    Returns:
        One :class:`ServiceMatches` per service, each with MSF candidates
        sorted by exploit rank (most reliable first).
    """
    all_matches: list[ServiceMatches] = []

    for service in services:
        if service.state != "open":
            continue

        matches = ServiceMatches(service=service)
        terms = _search_terms(service)
        if not terms:
            logger.info("Port %s: eşleştirecek ürün/sürüm yok, atlanıyor.", service.port)
            all_matches.append(matches)
            continue

        logger.info("Port %s eşleştiriliyor (%s) — terimler: %s", service.port, service.banner, terms)

        seen_modules: set[str] = set()
        for term in terms:
            for row in _search_msf(msf_client, term):
                module = row.get("fullname") or row.get("name", "")
                # Normalise "exploit/unix/..." -> "unix/..." for modules.use().
                module = module.split("exploit/", 1)[-1]
                if not module or module in seen_modules:
                    continue
                seen_modules.add(module)
                matches.msf_candidates.append(
                    ExploitCandidate(
                        module=module,
                        title=row.get("name") or row.get("fullname", module),
                        rank=str(row.get("rank", "normal")),
                        service_port=service.port,
                        service_name=service.name,
                        disclosure_date=str(row.get("disclosuredate", "")),
                    )
                )

            if use_searchsploit:
                for hit in _run_searchsploit(term):
                    matches.searchsploit_hits.append(hit)

        # Best (most reliable) exploits first.
        matches.msf_candidates.sort(key=lambda c: c.rank_score, reverse=True)
        logger.info(
            "  -> %d MSF adayı, %d Exploit-DB eşleşmesi",
            len(matches.msf_candidates),
            len(matches.searchsploit_hits),
        )
        all_matches.append(matches)

    return all_matches


def flatten_candidates(matches: Iterable[ServiceMatches]) -> list[ExploitCandidate]:
    """Return all MSF candidates across services, globally ranked.

    Candidates are ordered by exploit rank so the executor burns its limited
    attempt budget on the most reliable modules first.
    """
    candidates: list[ExploitCandidate] = []
    for m in matches:
        candidates.extend(m.msf_candidates)
    candidates.sort(key=lambda c: c.rank_score, reverse=True)
    return candidates
