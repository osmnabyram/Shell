"""Active web attack-surface recon via external tools.

The MSF ``http`` scanners in the playbook only scratch the web surface. On real
lab targets (and OSCP/CTF boxes) most footholds come from fingerprinting the web
stack, discovering hidden content, and running a template-based vulnerability
scanner. This module drives those best-in-class CLI tools against the single
target and turns their output into :class:`~core.strategy.Finding` objects that
feed straight back into the autonomous engine:

* ``whatweb``                 -> technology/product fingerprints
* ``nuclei``                  -> template-based CVE / misconfig / exposure checks
* ``gobuster`` / ``ffuf``     -> hidden directories and files
* ``nikto``                   -> classic web-server issues

Every tool is optional: whatever is not installed is skipped with a note (see
:mod:`core.tools`), so this degrades gracefully. A detected product becomes a
``product`` finding, which the strategy engine already knows how to turn into
knowledge-base and version-matched exploits -- so "nuclei saw Drupal" or
"gobuster found /manager/html" automatically widens the exploit plan.

Only the single provided target + its detected web ports are ever touched.
"""

from __future__ import annotations

import json
import logging
import re

from . import tools
from .recon import Service
from .strategy import Finding

logger = logging.getLogger("ShellCracker.webenum")

# Path / banner token -> product name the strategy KB understands. When one of
# these is seen (in a discovered path or a fingerprint), we emit a ``product``
# finding so the engine injects the matching exploits.
_PATH_PRODUCT: list[tuple[str, str]] = [
    ("/phpmyadmin", "phpmyadmin"),
    ("/wp-login.php", "wordpress"), ("/wp-admin", "wordpress"),
    ("/wp-content", "wordpress"),
    ("/administrator", "joomla"),
    ("/manager/html", "tomcat"), ("/host-manager", "tomcat"),
    ("/user/login", "drupal"), ("/CHANGELOG.txt", "drupal"),
    ("/jenkins", "jenkins"), ("/script", "jenkins"),
    ("/struts", "struts"), (".action", "struts"), (".do", "struts"),
    ("/cgi-bin/", "cgi"),
    ("/server-status", "apache"),
    ("/solr/", "solr"),
    ("/jmx-console", "jboss"), ("/web-console", "jboss"),
    ("/zabbix", "zabbix"),
    ("/grafana", "grafana"),
]

# Interesting exposures we record as facts/notes even without a product match.
_INTERESTING_PATHS = (
    "/.git/", "/.svn/", "/.env", "/backup", "/config", "/adminer",
    "/.ssh", "/phpinfo.php", "/server-info", "/actuator", "/debug",
)

_WHATWEB_PRODUCTS = (
    "wordpress", "joomla", "drupal", "tomcat", "jenkins", "jboss",
    "phpmyadmin", "apache", "nginx", "iis", "struts", "spring",
    "laravel", "django", "flask", "express", "grafana", "zabbix",
    "coldfusion", "weblogic", "websphere", "sharepoint", "citrix",
    "gitlab", "confluence", "jira", "solr", "elasticsearch", "kibana",
)


def _url(target: str, svc: Service) -> str:
    """Build the base URL for a web service (https when the port/banner is TLS)."""
    blob = f"{svc.name} {svc.extrainfo} {svc.product}".lower()
    tls = ("https" in blob or "ssl" in blob or "tls" in blob
           or svc.port in (443, 8443, 993, 995))
    scheme = "https" if tls else "http"
    return f"{scheme}://{target}:{svc.port}"


def parse_whatweb(text: str) -> list[str]:
    """Extract product names from whatweb output (plain or [key] tokens)."""
    low = text.lower()
    return [p for p in _WHATWEB_PRODUCTS if p in low]


def parse_nuclei(text: str) -> list[dict]:
    """Parse nuclei JSONL (``-jsonl``) output into a list of hit dicts."""
    hits: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        info = obj.get("info", {}) if isinstance(obj.get("info"), dict) else {}
        hits.append({
            "template": obj.get("template-id") or obj.get("templateID") or "",
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "").lower(),
            "matched": obj.get("matched-at") or obj.get("host") or "",
        })
    return hits


_GOBUSTER_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d{3})\)", re.M)
_FFUF_URL_RE = re.compile(r'"url"\s*:\s*"[^"]*?(/[^"]*)"')


def parse_paths(text: str) -> list[tuple[str, str]]:
    """Parse discovered paths from gobuster (``(Status: NNN)``) output."""
    out: list[tuple[str, str]] = []
    for m in _GOBUSTER_RE.finditer(text):
        out.append((m.group(1), m.group(2)))
    return out


def paths_to_products(paths: list[str]) -> list[str]:
    """Map discovered paths to KB product names (wordpress, tomcat, ...)."""
    found: list[str] = []
    joined = " ".join(p.lower() for p in paths)
    for token, product in _PATH_PRODUCT:
        if token.lower() in joined and product not in found:
            found.append(product)
    return found


class WebEnumRunner:
    """Runs the external web-recon tools against one target's web services."""

    def __init__(self, target: str, config: dict) -> None:
        self.target = target
        cfg = (config or {}).get("webenum", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.use_whatweb = bool(cfg.get("whatweb", True))
        self.use_nuclei = bool(cfg.get("nuclei", True))
        self.use_dirscan = bool(cfg.get("dirscan", True))
        self.use_nikto = bool(cfg.get("nikto", False))  # slow -> opt-in
        self.wordlist = str(cfg.get(
            "wordlist", "/usr/share/wordlists/dirb/common.txt"))
        self.nuclei_severity = str(cfg.get(
            "nuclei_severity", "low,medium,high,critical"))
        self.timeout = int(cfg.get("timeout", 300))

    # -- individual tools ----------------------------------------------------
    def _whatweb(self, url: str, svc: Service) -> list[Finding]:
        res = tools.run(["whatweb", "--color=never", "-a", "3", url],
                        timeout=min(self.timeout, 90))
        if not res.ok:
            return []
        out: list[Finding] = []
        for product in parse_whatweb(res.text):
            out.append(Finding(key="product", value=product, port=svc.port,
                               category="web", detail=f"whatweb: {product} @ {url}"))
        return out

    def _nuclei(self, url: str, svc: Service) -> list[Finding]:
        res = tools.run(
            ["nuclei", "-u", url, "-jsonl", "-silent", "-nc",
             "-severity", self.nuclei_severity],
            timeout=self.timeout,
        )
        if not res.ok and not res.stdout:
            return []
        out: list[Finding] = []
        for hit in parse_nuclei(res.text):
            label = f"nuclei[{hit['severity'] or '?'}] {hit['name'] or hit['template']}"
            out.append(Finding(
                key=f"nuclei.{hit['template'] or 'hit'}", value=hit,
                port=svc.port, category="web",
                detail=f"{label} -> {hit['matched']}",
            ))
            # If the template name/id names a product we know, trigger its exploits.
            blob = f"{hit['template']} {hit['name']}".lower()
            for product in _WHATWEB_PRODUCTS:
                if product in blob:
                    out.append(Finding(key="product", value=product, port=svc.port,
                                       category="web", detail=f"nuclei: {product}"))
                    break
        return out

    def _dirscan(self, url: str, svc: Service) -> list[Finding]:
        if tools.have("gobuster"):
            res = tools.run(
                ["gobuster", "dir", "-u", url, "-w", self.wordlist,
                 "-q", "-t", "30", "--no-error", "-z"],
                timeout=self.timeout,
            )
        elif tools.have("ffuf"):
            res = tools.run(
                ["ffuf", "-u", f"{url}/FUZZ", "-w", self.wordlist,
                 "-mc", "200,204,301,302,307,401,403", "-s"],
                timeout=self.timeout,
            )
        else:
            logger.info("  [atlandi] gobuster/ffuf kurulu degil.")
            return []
        if not res.ok and not res.stdout:
            return []

        paths = [p for p, _ in parse_paths(res.text)]
        # ffuf -s prints bare paths/words; fold those in too.
        if not paths:
            paths = [ln.strip() for ln in res.text.splitlines()
                     if ln.strip().startswith("/")]
        out: list[Finding] = []
        for product in paths_to_products(paths):
            out.append(Finding(key="product", value=product, port=svc.port,
                               category="web", detail=f"dirscan path -> {product}"))
        interesting = sorted({p for p in paths
                              if any(i in p.lower() for i in _INTERESTING_PATHS)})
        if interesting:
            out.append(Finding(
                key="web.exposed_paths", value=interesting, port=svc.port,
                category="web",
                detail="Ilginc yollar: " + ", ".join(interesting[:10]),
            ))
        if paths:
            out.append(Finding(key="web.paths", value=paths[:50], port=svc.port,
                               category="web",
                               detail=f"{len(paths)} yol kesfedildi ({url})"))
        return out

    def _nikto(self, url: str, svc: Service) -> list[Finding]:
        res = tools.run(
            ["nikto", "-host", url, "-ask", "no", "-nointeractive",
             "-Tuning", "123bde"],
            timeout=self.timeout,
        )
        if not res.ok and not res.stdout:
            return []
        notes = [ln.strip() for ln in res.text.splitlines()
                 if ln.strip().startswith("+") and "0 host(s) tested" not in ln]
        if not notes:
            return []
        return [Finding(key="web.nikto", value=notes[:40], port=svc.port,
                        category="web", detail=f"nikto: {len(notes)} bulgu ({url})")]

    # -- entry ---------------------------------------------------------------
    def scan_service(self, svc: Service) -> list[Finding]:
        """Run every enabled web tool against one web service and merge findings."""
        url = _url(self.target, svc)
        logger.info("Web keşfi: %s", url)
        findings: list[Finding] = []
        if self.use_whatweb:
            findings += self._whatweb(url, svc)
        if self.use_nuclei:
            findings += self._nuclei(url, svc)
        if self.use_dirscan:
            findings += self._dirscan(url, svc)
        if self.use_nikto:
            findings += self._nikto(url, svc)

        # De-duplicate identical product findings across tools.
        seen: set = set()
        unique: list[Finding] = []
        for f in findings:
            sig = (f.key, str(f.value), f.port)
            if sig in seen:
                continue
            seen.add(sig)
            unique.append(f)
        logger.info("  %s: %d bulgu", url, len(unique))
        return unique

    def tool_status(self) -> dict[str, bool]:
        """Which of the web tools are installed (for a one-line status line)."""
        return {t: tools.have(t) for t in
                ("whatweb", "nuclei", "gobuster", "ffuf", "nikto")}
