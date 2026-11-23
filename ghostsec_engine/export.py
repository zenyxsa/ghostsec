#!/usr/bin/env python3
"""Export saved GhostSec SQLite assessments as HTML or optional PDF."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import get_session


def _load_session(session_id: int, db_path=None) -> dict[str, Any]:
    if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id < 1:
        raise ValueError("Session ID must be a positive integer.")
    session = get_session(session_id, db_path=db_path)
    if session is None:
        raise ValueError("Assessment session {} was not found.".format(session_id))
    return session


def _filename_part(value: object) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value or "target"))
    return cleaned.strip("_")[:64] or "target"


def _render_html(session: dict[str, Any]) -> str:
    esc = lambda value: html.escape(str(value if value is not None else ""), quote=True)
    authorized = session.get("authorized_targets") or []
    meta_rows = [
        ("Session ID", session.get("id")),
        ("Status", session.get("status")),
        ("Risk level", session.get("risk_level") or "Not set"),
        ("Target", session.get("target")),
        ("Started", session.get("started_at")),
        ("Completed", session.get("completed_at") or "Not completed"),
        ("Objective", session.get("objective")),
        ("Assessment summary", session.get("summary") or "-"),
        ("Authorized scope", ", ".join(str(item) for item in authorized)),
    ]
    metadata = "\n".join(
        "<tr><th>{}</th><td>{}</td></tr>".format(esc(label), esc(value))
        for label, value in meta_rows
    )

    report = esc(session.get("report") or "No final report has been saved.")
    report_html = '<div class="report">{}</div>'.format(report)

    findings = session.get("findings") or []
    if findings:
        finding_rows = []
        for item in findings:
            finding_rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    esc(item.get("name")),
                    esc(str(item.get("severity") or "unknown").upper()),
                    esc(item.get("port") or "-"),
                    esc(item.get("service") or "-"),
                    esc(item.get("description") or item.get("evidence") or "-"),
                )
            )
        findings_html = (
            '<div class="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th>'
            '<th>Port</th><th>Service</th><th>Description / Evidence</th></tr></thead><tbody>'
            + "".join(finding_rows) + "</tbody></table></div>"
        )
    else:
        findings_html = '<p class="muted">No structured findings were saved for this session.</p>'

    results = session.get("tool_results") or []
    if results:
        result_sections = []
        for item in results:
            state = "SUCCESS" if item.get("ok") else "FAILED"
            payload = {
                "arguments": item.get("arguments", {}),
                "result": item.get("result"),
                "error": item.get("error"),
            }
            rendered = esc(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            result_sections.append(
                '<article class="tool"><h3>Round {} · {} · {}</h3><pre>{}</pre></article>'.format(
                    esc(item.get("round_number")), esc(item.get("tool_name")), esc(state), rendered
                )
            )
        tools_html = "".join(result_sections)
    else:
        tools_html = '<p class="muted">No tool executions were recorded.</p>'

    fixes = session.get("fixes") or []
    if fixes:
        fixes_html = "<ul>" + "".join(
            "<li>{} <span class=\"muted\">(source: {})</span></li>".format(
                esc(item.get("remediation")), esc(item.get("source") or "unknown")
            )
            for item in fixes
        ) + "</ul>"
    else:
        fixes_html = '<p class="muted">No remediations were saved for this session.</p>'

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    template = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GhostSec Assessment #{sid} — {target}</title>
<style>
:root {{ color-scheme: light; font-family: Inter, system-ui, sans-serif; color: #202733; background: #f3f5f8; }}
body {{ margin: 0; padding: 32px 16px; }} main {{ max-width: 1100px; margin: auto; background: #fff; padding: 32px; border: 1px solid #e1e5eb; border-radius: 14px; }}
h1 {{ margin: 0 0 6px; color: #a93226; }} .subtitle, .muted, footer {{ color: #667085; }}
h2 {{ margin-top: 30px; padding-bottom: 8px; border-bottom: 1px solid #e6e9ee; }}
table {{ width: 100%; border-collapse: collapse; }} th, td {{ text-align: left; vertical-align: top; padding: 10px; border: 1px solid #e3e7ed; overflow-wrap: anywhere; }}
thead th {{ background: #263445; color: #fff; }}
.meta th {{ width: 190px; background: #f7f8fa; }} .report {{ white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.55; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f6f7f9; padding: 14px; border-radius: 8px; }}
.tool {{ margin: 14px 0; }} .tool h3 {{ font-size: 15px; }} .table-wrap {{ overflow-x: auto; }}
footer {{ margin-top: 32px; font-size: 12px; }}
@media (max-width: 640px) {{ main {{ padding: 18px; }} body {{ padding: 12px 6px; }} .meta th {{ width: 110px; }} }}
@media print {{ body {{ background: #fff; padding: 0; }} main {{ border: 0; padding: 0; }} }}
</style>
</head>
<body><main>
<header><h1>GHOSTSEC</h1><div class="subtitle">Defensive Security Assessment · Session #{sid}</div></header>
<h2>Assessment details</h2><table class="meta"><tbody>{metadata}</tbody></table>
<h2>Final assessment report</h2>{report_html}
<h2>Structured findings</h2>{findings_html}
<h2>Tool execution history</h2>{tools_html}
<h2>Remediations</h2>{fixes_html}
<footer>Generated {generated}. GhostSec assessment output. For authorized use only. Validate findings before acting on them.</footer>
</main></body></html>'''
    return template.format(
        sid=esc(session.get("id")), target=esc(session.get("target")), metadata=metadata,
        report_html=report_html, findings_html=findings_html, tools_html=tools_html,
        fixes_html=fixes_html, generated=esc(generated),
    )


def export_html(session_id: int, output_dir: str | Path = "reports", db_path=None) -> str:
    session = _load_session(session_id, db_path=db_path)
    folder = Path(output_dir).expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    filename = "ghostsec_session_{}_{}.html".format(
        session_id, _filename_part(session.get("target"))
    )
    destination = folder / filename
    destination.write_text(_render_html(session), encoding="utf-8")
    return str(destination)


def export_pdf(session_id: int, output_dir: str | Path = "reports", db_path=None) -> str:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
        from xml.sax.saxutils import escape
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires ReportLab. Install it with: python3 -m pip install reportlab"
        ) from exc

    session = _load_session(session_id, db_path=db_path)
    folder = Path(output_dir).expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    filename = "ghostsec_session_{}_{}.pdf".format(
        session_id, _filename_part(session.get("target"))
    )
    destination = folder / filename

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="GhostTitle", parent=styles["Title"], textColor=colors.HexColor("#a93226")))
    styles.add(ParagraphStyle(name="GhostSmall", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="GhostCode", parent=styles["Code"], fontSize=7, leading=9, wordWrap="CJK"))
    story = [Paragraph("GHOSTSEC", styles["GhostTitle"]),
             Paragraph("Defensive Security Assessment · Session #{}".format(session_id), styles["Normal"]),
             Spacer(1, 8)]

    metadata = [
        ["Field", "Value"],
        ["Status", str(session.get("status") or "-")],
        ["Risk level", str(session.get("risk_level") or "Not set")],
        ["Target", str(session.get("target") or "-")],
        ["Started", str(session.get("started_at") or "-")],
        ["Completed", str(session.get("completed_at") or "Not completed")],
        ["Objective", str(session.get("objective") or "-")],
        ["Assessment summary", str(session.get("summary") or "-")],
        ["Authorized scope", ", ".join(session.get("authorized_targets") or [])],
    ]
    table = Table([[Paragraph(escape(str(cell)), styles["GhostSmall"]) for cell in row] for row in metadata], colWidths=[35 * mm, 135 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263445")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae1")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.extend([table, Spacer(1, 12), Paragraph("Final assessment report", styles["Heading2"]),
                  Preformatted(str(session.get("report") or "No final report saved."), styles["GhostCode"]),
                  Paragraph("Structured findings", styles["Heading2"])])

    findings = session.get("findings") or []
    if findings:
        finding_data = [["Finding", "Severity", "Port", "Service", "Description"]]
        for item in findings:
            finding_data.append([Paragraph(escape(str(item.get("name") or "-")), styles["GhostSmall"]),
                                 str(item.get("severity") or "unknown").upper(),
                                 str(item.get("port") or "-"), str(item.get("service") or "-"),
                                 Paragraph(escape(str(item.get("description") or item.get("evidence") or "-")), styles["GhostSmall"])])
        ft = Table(finding_data, repeatRows=1, colWidths=[38*mm, 22*mm, 16*mm, 25*mm, 69*mm])
        ft.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#263445")),
                                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                                ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5dae1")),
                                ("FONTSIZE", (0,0), (-1,-1), 7), ("VALIGN", (0,0), (-1,-1), "TOP"),
                                ("PADDING", (0,0), (-1,-1), 4)]))
        story.append(ft)
    else:
        story.append(Paragraph("No structured findings were saved.", styles["BodyText"]))

    story.append(Paragraph("Tool execution history", styles["Heading2"]))
    for item in session.get("tool_results") or []:
        state = "SUCCESS" if item.get("ok") else "FAILED"
        story.append(Paragraph("Round {} · {} · {}".format(
            escape(str(item.get("round_number"))), escape(str(item.get("tool_name"))), state
        ), styles["Heading3"]))
        body = {"arguments": item.get("arguments", {}), "result": item.get("result"), "error": item.get("error")}
        story.append(Preformatted(json.dumps(body, ensure_ascii=False, indent=2, default=str), styles["GhostCode"]))

    story.append(Paragraph("Remediations", styles["Heading2"]))
    fixes = session.get("fixes") or []
    if fixes:
        for item in fixes:
            story.append(Paragraph("- " + escape(str(item.get("remediation") or "-")), styles["BodyText"]))
    else:
        story.append(Paragraph("No remediations were saved.", styles["BodyText"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Generated by GhostSec. For authorized use only. Validate findings before acting on them.", styles["GhostSmall"]))
    SimpleDocTemplate(str(destination), pagesize=A4, rightMargin=15*mm, leftMargin=15*mm,
                      topMargin=15*mm, bottomMargin=15*mm).build(story)
    return str(destination)


def export_session(
    session_id: int,
    output_dir: str | Path = "reports",
    format: str = "html",
    db_path=None,
) -> dict[str, str]:
    selected = format.lower()
    if selected not in {"html", "pdf", "both"}:
        raise ValueError("Export format must be html, pdf, or both.")
    outputs: dict[str, str] = {}
    if selected in {"pdf", "both"}:
        outputs["pdf"] = export_pdf(session_id, output_dir=output_dir, db_path=db_path)
    if selected in {"html", "both"}:
        outputs["html"] = export_html(session_id, output_dir=output_dir, db_path=db_path)
    return outputs
