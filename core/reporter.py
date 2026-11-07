"""Reporting: persist run results as timestamped JSON and Markdown.

Every run produces two artefacts under ``reports/``:

* ``ShellCracker_<target>_<timestamp>.json`` -- machine-readable, the full record
  of recon, matches and every attempt (parameters, check result, reason).
* ``ShellCracker_<target>_<timestamp>.md``   -- human-readable summary.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("ShellCracker.reporter")


def build_report(
    target: str,
    consent: bool,
    recon: Any,
    matches: list[Any],
    attempts: list[Any],
    profile: Any = None,
    plan: Any = None,
) -> dict[str, Any]:
    """Assemble the full run record as a plain dict."""
    successful = [a for a in attempts if getattr(a, "success", False)]
    report = {
        "tool": "ShellCracker",
        "target": target,
        "authorized_consent": consent,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "open_services": len(recon.open_services()) if recon else 0,
            "os_family": getattr(profile, "os_family", "unknown") if profile else "unknown",
            "candidates_considered": sum(len(m.msf_candidates) for m in matches),
            "vectors_planned": len(plan.all()) if plan is not None else 0,
            "attempts": len(attempts),
            "sessions_obtained": len(successful),
            "outcome": "shell" if successful else "no-shell",
        },
        "recon": {
            "started_at": getattr(recon, "started_at", ""),
            "finished_at": getattr(recon, "finished_at", ""),
            "raw_xml": getattr(recon, "raw_xml_path", None),
            "services": [s.to_dict() for s in recon.open_services()] if recon else [],
        },
        "matches": [m.to_dict() for m in matches],
        "attempts": [a.to_dict() for a in attempts],
    }
    if profile is not None:
        report["profile"] = profile.to_dict()
    if plan is not None:
        report["plan"] = [v.to_dict() for v in plan.all()]
    return report


def _render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    outcome_tr = {"shell": "shell alindi", "no-shell": "shell yok"}.get(
        s["outcome"], s["outcome"]
    )
    lines = [
        f"# ShellCracker raporu — {report['target']}",
        "",
        f"- **Olusturulma:** {report['generated_at']}",
        f"- **Kayitli yetki onayi:** {report['authorized_consent']}",
        f"- **Sonuc:** {outcome_tr}",
        f"- **Tahmini OS:** {s.get('os_family', 'unknown')}",
        f"- **Acik servisler:** {s['open_services']}",
        f"- **Planlanan vektor:** {s.get('vectors_planned', 0)}",
        f"- **Degerlendirilen aday:** {s['candidates_considered']}",
        f"- **Deneme sayisi:** {s['attempts']}",
        f"- **Alinan oturum:** {s['sessions_obtained']}",
        "",
    ]

    # Target profile (autonomous engine).
    prof = report.get("profile")
    if prof:
        lines += [
            "## Hedef profili",
            "",
            f"- **OS ailesi:** {prof['os_family']} "
            f"(%{int(prof['os_confidence'] * 100)}, {prof['os_details']})",
            f"- **Kategoriler:** "
            + (", ".join(f"{c} ({len(p)})" for c, p in prof["categories"].items()) or "yok"),
        ]
        if prof.get("facts"):
            lines.append(f"- **Bulgular:** `{prof['facts']}`")
        for note in prof.get("notes", []):
            lines.append(f"  - {note}")
        lines.append("")

    # Attack plan (scored decision tree).
    plan = report.get("plan")
    if plan:
        lines += [
            "## Saldiri plani (skorlu karar agaci)",
            "",
            "| Faz | Tur | Modul | Port | Skor | Gerekce |",
            "| --- | --- | ----- | ---- | ---- | ------- |",
        ]
        for v in sorted(plan, key=lambda x: (x["phase"], -x["score"])):
            lines.append(
                f"| {v['phase']} | {v['kind']} | `{v['module']}` | {v['port']} | "
                f"{v['score']} | {v['rationale']} |"
            )
        lines.append("")

    lines += [
        "## Acik servisler",
        "",
        "| Port | Proto | Servis | Surum |",
        "| ---- | ----- | ------ | ----- |",
    ]
    for svc in report["recon"]["services"]:
        lines.append(
            f"| {svc['port']} | {svc['protocol']} | {svc['name']} | "
            f"{svc['banner']} |"
        )

    lines += ["", "## Denemeler", ""]
    if not report["attempts"]:
        lines.append("_Hic exploit denemesi yapilmadi._")
    for i, a in enumerate(report["attempts"], start=1):
        status = "✅ BASARILI" if a["success"] else "❌ basarisiz"
        kind = a.get("kind", "exploit")
        prefix = "exploit" if kind == "exploit" else "auxiliary"
        lines += [
            f"### {i}. `{prefix}/{a['module']}` — {status}",
            "",
            f"- **Faz / tur:** {a.get('phase', '?')} / {kind}"
            + (f"  (skor {a.get('score', 0)})" if a.get("score") else ""),
        ]
        if a.get("rationale"):
            lines.append(f"- **Gerekce:** {a['rationale']}")
        if kind == "exploit":
            lines += [
                f"- **Payload:** `{a['payload']}`",
                f"- **check():** {a['check_result']}",
            ]
        lines += [
            f"- **Parametreler:** `{a['parameters']}`",
            f"- **Ateslendi:** {a['fired']}",
            f"- **Neden:** {a['reason']}",
        ]
        if a.get("findings"):
            lines.append(f"- **Bulgular:** {', '.join(a['findings'])}")
        if a["session_id"] is not None:
            lines.append(f"- **Oturum:** {a['session_id']} ({a['session_type']})")
        if a["proof"]:
            lines += ["", "```", a["proof"], "```"]
        pe = a.get("postexp") or {}
        if pe:
            lines += [
                "",
                "#### Post-exploitation",
                f"- **Kullanici:** `{pe.get('whoami', '').splitlines()[0] if pe.get('whoami') else '?'}`"
                + ("  — **ROOT/SYSTEM**" if pe.get("is_privileged") else "  — sinirli"),
            ]
            if pe.get("escalated"):
                lines.append("- **Yetki yukseltme:** basarili (getsystem)")
            if pe.get("privesc_suggestions"):
                lines.append("- **Privesc onerileri:**")
                for sug in pe["privesc_suggestions"][:8]:
                    lines.append(f"  - {sug}")
            if pe.get("loot"):
                shown = [k for k, v in pe["loot"].items() if v and not v.startswith("[hata")]
                if shown:
                    lines.append(f"- **Toplanan:** {', '.join(shown)}")
        lines.append("")

    lines += [
        "---",
        "",
        "_ShellCracker tarafindan olusturuldu. Yalnizca yetkili lab kullanimi._",
    ]
    return "\n".join(lines)


def write_reports(report: dict[str, Any], reports_dir: str | Path = "reports") -> tuple[str, str]:
    """Write JSON and Markdown reports. Returns (json_path, md_path)."""
    out = Path(reports_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = report["target"].replace(":", "_").replace("/", "_")
    stem = f"ShellCracker_{safe_target}_{ts}"

    json_path = out / f"{stem}.json"
    md_path = out / f"{stem}.md"

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    md_path.write_text(_render_markdown(report))

    logger.info("Raporlar yazildi:\n  %s\n  %s", json_path, md_path)
    return str(json_path), str(md_path)
