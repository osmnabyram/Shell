"""Target profiling: turn raw recon output into a structured target model.

The matcher/executor used to work straight off the flat service list. The
autonomous engine needs something richer to reason over, so this module builds
a :class:`TargetProfile`:

* services grouped into **categories** (web / smb / ftp / ssh / database / ...),
  because the attack playbook is organised per category;
* a best-effort **OS family** guess (windows / linux / unix / unknown) with a
  confidence score, inferred from OS fingerprints and service banners;
* a mutable **facts** knowledge base (``profile.facts``) that the strategy and
  executor keep extending as enumeration reveals more (anonymous FTP, SMB null
  sessions, discovered credentials, ...), so later decisions can use it.

Profiling never touches the target; it only interprets what recon already saw.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable

from .recon import ReconResult, Service

logger = logging.getLogger("ShellCracker.profiler")


# --- Service categorisation -------------------------------------------------
# A service is placed in the FIRST category whose name-set or product-keyword
# matches. Categories drive which branch of the attack playbook runs.
_CATEGORY_NAMES: dict[str, set[str]] = {
    "web": {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http",
            "http-mgmt", "soap", "upnp"},
    "smb": {"microsoft-ds", "netbios-ssn", "netbios-ns", "smb"},
    "ftp": {"ftp", "ftps", "ftp-data"},
    "ssh": {"ssh"},
    "telnet": {"telnet"},
    "rdp": {"ms-wbt-server", "rdp"},
    "mysql": {"mysql"},
    "mssql": {"ms-sql-s", "ms-sql"},
    "postgres": {"postgresql", "postgres"},
    "oracle": {"oracle-tns", "oracle"},
    "mongodb": {"mongodb", "mongod"},
    "redis": {"redis"},
    "rpc": {"rpcbind", "nfs", "msrpc", "mountd", "nlockmgr", "nfs_acl"},
    "smtp": {"smtp", "smtps", "submission"},
    "pop3": {"pop3", "pop3s"},
    "imap": {"imap", "imaps"},
    "dns": {"domain", "dns"},
    "snmp": {"snmp", "snmptrap"},
    "vnc": {"vnc", "vnc-http"},
    "irc": {"irc", "ircs", "ircu", "ircd"},
    "finger": {"finger"},
    "rservices": {"exec", "login", "shell", "rexec", "rlogin", "rsh"},
    "java-rmi": {"java-rmi", "rmiregistry"},
    "ajp": {"ajp13", "ajp"},
    "distcc": {"distccd", "distcc"},
}
# Fallback: keyword in product/extrainfo -> category, when the service name is
# generic (e.g. "tcpwrapped" or an unrecognised banner).
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("web", ("apache", "nginx", "iis", "tomcat", "jetty", "lighttpd", "httpd",
             "werkzeug", "node.js", "php", "wordpress", "drupal", "joomla")),
    ("smb", ("samba", "cifs")),
    ("database", ("mariadb", "couchdb", "memcached", "elasticsearch")),
]

# Service categories most likely to hand over a shell / high-value foothold get
# a higher base weight; purely informational ones get less. Used by the scorer.
CATEGORY_WEIGHT: dict[str, int] = {
    "smb": 26, "ftp": 24, "web": 22, "telnet": 21, "rservices": 22,
    "mysql": 20, "mssql": 20, "postgres": 20, "rdp": 20, "vnc": 20,
    "java-rmi": 22, "irc": 20, "distcc": 22, "ajp": 18,
    "ssh": 18, "redis": 19, "mongodb": 18, "oracle": 18,
    "rpc": 16, "snmp": 16, "smtp": 14, "pop3": 12, "imap": 12,
    "finger": 12, "dns": 8, "database": 18, "other": 8,
}

# --- OS inference signals ---------------------------------------------------
_WINDOWS_HINTS = ("microsoft", "windows", "win32", "win64", "iis", ".net",
                  "ms-wbt", "netbios", "microsoft-ds", "msrpc", "winrm")
_LINUX_HINTS = ("linux", "ubuntu", "debian", "fedora", "centos", "red hat",
                "redhat", "gentoo", "mint", "raspbian")
_UNIX_HINTS = ("unix", "bsd", "solaris", "aix", "hp-ux", "freebsd", "openbsd")


@dataclass
class TargetProfile:
    """A structured, reason-over-able model of a single target."""

    target: str
    services: list[Service] = field(default_factory=list)
    categorized: dict[str, list[Service]] = field(default_factory=dict)
    os_family: str = "unknown"          # windows | linux | unix | unknown
    os_confidence: float = 0.0          # 0.0 .. 1.0
    os_details: str = ""
    # Mutable knowledge base extended during the run. Keys are dotted strings,
    # e.g. "ftp.anonymous" -> True, "smb.shares" -> ["tmp", "..."], "creds" ->
    # [{"service": "ssh", "port": 22, "user": "...", "password": "..."}].
    facts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def categories(self) -> list[str]:
        """Categories actually present on the target, most-weighted first."""
        return sorted(
            self.categorized.keys(),
            key=lambda c: CATEGORY_WEIGHT.get(c, 0),
            reverse=True,
        )

    def add_fact(self, key: str, value: Any) -> None:
        """Record a discovered fact; list-valued facts accumulate uniquely."""
        if isinstance(value, (list, tuple)):
            bucket = self.facts.setdefault(key, [])
            for v in value:
                if v not in bucket:
                    bucket.append(v)
        else:
            self.facts[key] = value

    def add_credential(self, service: str, port: int, user: str, password: str) -> None:
        """Store a discovered credential (de-duplicated)."""
        creds = self.facts.setdefault("creds", [])
        entry = {"service": service, "port": port, "user": user, "password": password}
        if entry not in creds:
            creds.append(entry)
            self.notes.append(f"Kimlik bulundu: {service}:{port} {user}:{password or '<bos>'}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "os_family": self.os_family,
            "os_confidence": round(self.os_confidence, 2),
            "os_details": self.os_details,
            "categories": {
                cat: [s.port for s in svcs] for cat, svcs in self.categorized.items()
            },
            "facts": self.facts,
            "notes": self.notes,
        }


def categorize_service(service: Service) -> str:
    """Map one service to its attack category (see ``_CATEGORY_NAMES``)."""
    name = (service.name or "").lower()
    for category, names in _CATEGORY_NAMES.items():
        if name in names:
            return category

    haystack = " ".join(
        (service.name, service.product, service.extrainfo, service.cpe)
    ).lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(k in haystack for k in keywords):
            return category
    return "other"


def _score_os_hints(haystack: str) -> dict[str, int]:
    """Count OS-family keyword hits inside a lowercased haystack string."""
    scores = {"windows": 0, "linux": 0, "unix": 0}
    for hint in _WINDOWS_HINTS:
        if hint in haystack:
            scores["windows"] += 1
    for hint in _LINUX_HINTS:
        if hint in haystack:
            scores["linux"] += 1
    for hint in _UNIX_HINTS:
        if hint in haystack:
            scores["unix"] += 1
    return scores


def infer_os(
    services: Iterable[Service], os_matches: list[dict[str, Any]] | None = None
) -> tuple[str, float, str]:
    """Infer (family, confidence, details) from OS fingerprints + banners.

    ``os_matches`` is nmap's ``osmatch`` list (only present when the scan used
    ``-O``). When absent, inference falls back to service banner keywords.
    """
    # 1. Trust an explicit nmap OS match the most, if we have one.
    if os_matches:
        best = max(os_matches, key=lambda m: int(m.get("accuracy", 0) or 0))
        name = str(best.get("name", ""))
        acc = int(best.get("accuracy", 0) or 0)
        hits = _score_os_hints(name.lower())
        family = max(hits, key=hits.get) if any(hits.values()) else "unknown"
        if family != "unknown":
            return family, min(0.5 + acc / 200.0, 0.99), f"nmap: {name} (%{acc})"

    # 2. Otherwise accumulate banner evidence across all services.
    totals = {"windows": 0, "linux": 0, "unix": 0}
    evidence: list[str] = []
    for svc in services:
        haystack = " ".join(
            (svc.name, svc.product, svc.version, svc.extrainfo, svc.cpe)
        ).lower()
        hits = _score_os_hints(haystack)
        for fam, n in hits.items():
            totals[fam] += n
        if any(hits.values()) and svc.product:
            evidence.append(svc.product)

    if not any(totals.values()):
        return "unknown", 0.0, "yeterli iz yok"

    # linux is a subset of unix; collapse unix into linux only if linux absent.
    if totals["linux"] == 0 and totals["unix"] > 0:
        family = "unix"
    else:
        family = max(totals, key=totals.get)
    top = totals[family]
    total = sum(totals.values()) or 1
    confidence = min(0.3 + 0.6 * (top / total), 0.9)
    detail = f"banner izleri ({top}/{total})" + (
        f": {', '.join(sorted(set(evidence))[:4])}" if evidence else ""
    )
    return family, confidence, detail


def build_profile(
    recon: ReconResult, os_matches: list[dict[str, Any]] | None = None
) -> TargetProfile:
    """Build a :class:`TargetProfile` from a recon result."""
    open_services = recon.open_services()
    profile = TargetProfile(target=recon.target, services=list(open_services))

    for svc in open_services:
        category = categorize_service(svc)
        profile.categorized.setdefault(category, []).append(svc)

    family, confidence, details = infer_os(open_services, os_matches)
    profile.os_family = family
    profile.os_confidence = confidence
    profile.os_details = details

    logger.info(
        "Profil: OS=%s (%.0f%%, %s) — %d kategori: %s",
        family, confidence * 100, details,
        len(profile.categorized),
        ", ".join(f"{c}×{len(s)}" for c, s in profile.categorized.items()),
    )
    return profile
