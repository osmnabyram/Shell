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
) -> dict[str, Any]:
    """Assemble the full run record as a plain dict."""
    successful = [a for a in attempts if getattr(a, "success", False)]
    return {
        "tool": "ShellCracker",
        "target": target,
        "authorized_consent": consent,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "open_services": len(recon.open_services()) if recon else 0,
            "candidates_considered": sum(len(m.msf_candidates) for m in matches),
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
        f"- **Acik servisler:** {s['open_services']}",
        f"- **Degerlendirilen aday:** {s['candidates_considered']}",
        f"- **Deneme sayisi:** {s['attempts']}",
        f"- **Alinan oturum:** {s['sessions_obtained']}",
        "",
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
        lines += [
            f"### {i}. `exploit/{a['module']}` — {status}",
            "",
            f"- **Payload:** `{a['payload']}`",
            f"- **Parametreler:** `{a['parameters']}`",
            f"- **check():** {a['check_result']}",
            f"- **Ateslendi:** {a['fired']}",
            f"- **Neden:** {a['reason']}",
        ]
        if a["session_id"] is not None:
            lines.append(f"- **Oturum:** {a['session_id']} ({a['session_type']})")
        if a["proof"]:
            lines += ["", "```", a["proof"], "```"]
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
