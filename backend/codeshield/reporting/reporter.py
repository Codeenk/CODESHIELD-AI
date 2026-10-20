"""JSON, SARIF 2.1.0, standalone HTML, and PDF exports."""
from __future__ import annotations

import html
import io
import json
from datetime import datetime, timezone
from typing import Any

from .. import config
from ..privacy import mask_text
from ..schemas import Finding, Scan

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _active(scan: Scan) -> list[Finding]:
    return [finding for finding in scan.findings if not finding.suppressed]


def build_json(scan: Scan) -> str:
    payload = scan.model_dump(mode="json")
    for finding in payload.get("findings", []):
        finding["function_source"] = mask_text(finding.get("function_source", ""))
    return json.dumps(payload, indent=2, default=str)


def build_sarif(scan: Scan) -> dict[str, Any]:
    results = []
    rules: dict[str, dict[str, Any]] = {}
    for finding in _active(scan):
        rule_id = finding.cwe
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.cwe_title.replace(" ", ""),
                "shortDescription": {"text": finding.cwe_title},
                "help": {
                    "text": (finding.explanation or {}).get("why", finding.message),
                    "markdown": (finding.explanation or {}).get("why", finding.message),
                },
                "properties": {
                    "tags": [finding.owasp] if finding.owasp else [],
                    "security-severity": _security_score(finding.severity),
                },
            }
        line = finding.evidence[0].line if finding.evidence else finding.start_line
        snippet = finding.evidence[0].snippet if finding.evidence else ""
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": f"{finding.cwe_title}: {finding.message} ({finding.path}:{line})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": line, "endLine": line,
                                "snippet": {"text": mask_text(snippet)},
                            },
                        },
                        "logicalLocations": [{"name": finding.function, "kind": "function"}],
                    }
                ],
                "partialFingerprints": {"codeshield/v1": finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "engine": finding.engine,
                    "verification": (
                        finding.patch_candidates[0].verification if finding.patch_candidates else "unverified"
                    ),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": config.APP_NAME,
                        "version": config.VERSION,
                        "informationUri": "https://github.com/Codeenk/CODESHIELD-AI",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan.status == "completed",
                        "startTimeUtc": (scan.started_at or scan.created_at).isoformat(),
                        "endTimeUtc": (scan.finished_at or scan.created_at).isoformat(),
                    }
                ],
                "properties": {"target": scan.target, "scanId": scan.id},
            }
        ],
    }


def _security_score(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}.get(severity, "5.0")


def _bar(value: int, maximum: int, color: str) -> str:
    width = 0 if not maximum else max(2, round(value / maximum * 100))
    return f'<div class="bar"><span style="width:{width}%;background:{color}"></span></div>'


def build_html(scan: Scan) -> str:
    summary = scan.summary
    severity_colors = {
        "critical": "#c2410c", "high": "#dc2626", "medium": "#d97706",
        "low": "#2563eb", "info": "#64748b",
    }
    max_sev = max(summary.by_severity.values(), default=1)
    severity_rows = "".join(
        f"<div class='metric'><span>{_SEVERITY_LABEL.get(key, key)}</span>"
        f"<strong>{value}</strong>{_bar(value, max_sev, severity_colors.get(key, '#64748b'))}</div>"
        for key, value in sorted(summary.by_severity.items(), key=lambda kv: -config.SEVERITY_ORDER.get(kv[0], 0))
    )
    findings_html = []
    for finding in _active(scan):
        evidence = "".join(
            f"<div class='ev'><code>{item.line}</code><pre>{html.escape(mask_text(item.snippet))}</pre>"
            f"<span>{html.escape(item.reason)}</span></div>"
            for item in finding.evidence[:6]
        )
        patches = "".join(
            f"<details><summary>{html.escape(patch.summary)} "
            f"<span class='pill {patch.verification.replace('_', '-')}'>{patch.verification.replace('_', ' ')}</span>"
            f"{' <span class=\"pill risk\">semantic risk</span>' if patch.semantic_risk else ''}</summary>"
            f"<pre class='diff'>{html.escape(mask_text(patch.unified_diff))}</pre>"
            f"<p class='muted'>{html.escape(patch.rationale)}</p></details>"
            for patch in finding.patch_candidates
        ) or "<p class='muted'>No verified repair generated. Review the remediation guidance.</p>"
        remediation = "".join(
            f"<li>{html.escape(item)}</li>" for item in (finding.explanation or {}).get("remediation", [])
        )
        findings_html.append(
            f"""
            <article class="finding">
              <header>
                <div><span class="sev {finding.severity}">{_SEVERITY_LABEL.get(finding.severity, finding.severity)}</span>
                <span class="cwe">{html.escape(finding.cwe)}</span></div>
                <span class="conf">{round(finding.confidence * 100)}% confidence · {finding.engine}</span>
              </header>
              <h3>{html.escape(finding.cwe_title)}</h3>
              <p class="loc"><code>{html.escape(finding.path)}</code> · {html.escape(finding.function)} · line {finding.evidence[0].line if finding.evidence else finding.start_line}</p>
              <p>{html.escape(finding.message)}</p>
              <h4>Evidence</h4>
              {evidence}
              <h4>Why this matters</h4>
              <p>{html.escape((finding.explanation or {}).get("why", ""))}</p>
              <h4>Remediation</h4>
              <ul>{remediation}</ul>
              <h4>Proposed repair</h4>
              {patches}
            </article>
            """
        )
    notes = "".join(f"<li>{html.escape(note)}</li>" for note in summary.engine_notes)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(config.APP_NAME)} report · {html.escape(scan.project_name or scan.target)}</title>
<style>
:root {{ --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --paper:#fbfaf7; --accent:#c2410c; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--paper); color:var(--ink); font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
.shell {{ max-width:960px; margin:0 auto; padding:48px 28px 80px; }}
.eyebrow {{ font:600 11px/1 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.14em; text-transform:uppercase; color:var(--accent); }}
h1 {{ font-size:34px; letter-spacing:-.03em; margin:10px 0 4px; }}
h2 {{ font-size:18px; margin:36px 0 12px; }}
h3 {{ font-size:17px; margin:8px 0 6px; }}
h4 {{ font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); margin:18px 0 8px; }}
.lede {{ color:var(--muted); margin:0; }}
.cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:24px; }}
.card {{ background:white; border:1px solid var(--line); border-radius:10px; padding:14px; }}
.card b {{ display:block; font-size:24px; letter-spacing:-.02em; }}
.card span {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px; }}
.metric {{ display:grid; grid-template-columns:80px 26px 1fr; gap:8px; align-items:center; font-size:12px; }}
.bar {{ height:6px; background:#ece9e2; border-radius:99px; overflow:hidden; }}
.bar span {{ display:block; height:100%; border-radius:99px; }}
.finding {{ background:white; border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin:12px 0; }}
.finding header {{ display:flex; justify-content:space-between; gap:10px; align-items:center; }}
.sev,.pill {{ font:600 10px/1 ui-monospace,monospace; text-transform:uppercase; letter-spacing:.08em; padding:5px 8px; border-radius:99px; background:#f3f4f6; }}
.sev.critical {{ background:#ffedd5; color:#9a3412; }} .sev.high {{ background:#fee2e2; color:#b91c1c; }}
.sev.medium {{ background:#fef3c7; color:#92400e; }} .sev.low {{ background:#dbeafe; color:#1d4ed8; }}
.verified {{ background:#dcfce7; color:#166534; }} .partially-verified {{ background:#fef3c7; color:#92400e; }}
.unverified {{ background:#fee2e2; color:#991b1b; }} .risk {{ background:#fde68a; color:#78350f; }}
.cwe, .conf, .loc {{ font-family:ui-monospace,monospace; font-size:11px; color:var(--muted); }}
.loc code {{ color:var(--ink); }}
.ev {{ display:grid; grid-template-columns:44px 1fr; gap:10px; border-left:2px solid var(--accent); padding:8px 0 8px 8px; margin:6px 0; }}
.ev code {{ color:var(--muted); font-size:11px; padding-top:2px; }}
.ev pre {{ margin:0; overflow:auto; font-size:12px; }}
.ev span {{ grid-column:2; color:var(--muted); font-size:12px; }}
details {{ border-top:1px dashed var(--line); padding:8px 0; }}
summary {{ cursor:pointer; font-weight:600; }}
pre.diff {{ background:#0f172a; color:#e2e8f0; padding:14px; border-radius:8px; overflow:auto; font-size:12px; }}
.muted {{ color:var(--muted); font-size:12px; }}
footer {{ margin-top:40px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:11px; }}
@media print {{ body {{ background:white; }} .shell {{ padding:0; }} .finding {{ break-inside:avoid; }} }}
@media (max-width:720px) {{ .cards {{ grid-template-columns:1fr 1fr; }} .grid {{ grid-template-columns:1fr; }} }}
</style></head><body><main class="shell">
<p class="eyebrow">Security assessment · {html.escape(config.APP_NAME)}</p>
<h1>{html.escape(scan.project_name or "Code scan")}</h1>
<p class="lede">{html.escape(scan.target)} · {html.escape(scan.source_type)} · generated {generated}</p>
<div class="cards">
  <div class="card"><span>Findings</span><b>{summary.total_findings}</b></div>
  <div class="card"><span>Files</span><b>{summary.files_scanned}</b></div>
  <div class="card"><span>Units</span><b>{summary.units_scanned}</b></div>
  <div class="card"><span>Suppressed</span><b>{summary.suppressed}</b></div>
</div>
<div class="grid">
<section><h2>Severity</h2>{severity_rows or '<p class="muted">No findings.</p>'}</section>
<section><h2>Engine</h2><ul>{notes}</ul>
<p class="muted">Model: {html.escape(summary.model_id or 'not enabled')} · Duration: {round(summary.duration_ms / 1000, 1)}s</p></section>
</div>
<h2>Findings</h2>
{''.join(findings_html) or '<p class="muted">No active findings.</p>'}
<footer>{html.escape(config.APP_NAME)} {config.VERSION} · Findings are candidates for review, not a guarantee of exploitability. Source excerpts are redacted when secret masking is enabled.</footer>
</main></body></html>"""


def build_pdf(scan: Scan) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"{config.APP_NAME} report", author=config.APP_NAME,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Kicker", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#9a3412"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Title2", parent=styles["Title"], fontSize=24, alignment=0, spaceAfter=4))
    styles.add(ParagraphStyle(name="Body2", parent=styles["BodyText"], fontSize=9, leading=13))
    styles.add(ParagraphStyle(name="Small2", parent=styles["BodyText"], fontSize=7.5, leading=10, textColor=colors.HexColor("#6b7280")))
    styles.add(ParagraphStyle(name="H2v", parent=styles["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="H3v", parent=styles["Heading3"], fontSize=10.5, spaceBefore=8, spaceAfter=3))

    def p(text: str, style: str = "Body2") -> Paragraph:
        return Paragraph(html.escape(text).replace("\n", "<br/>"), styles[style])

    story = [
        p("SECURITY ASSESSMENT", "Kicker"),
        p(scan.project_name or "Code scan", "Title2"),
        p(f"{scan.target} · {scan.source_type} · {scan.created_at.strftime('%Y-%m-%d %H:%M UTC')}", "Small2"),
        Spacer(1, 8),
        Table(
            [
                ["Findings", "Critical", "High", "Medium", "Files", "Units"],
                [
                    str(scan.summary.total_findings),
                    str(scan.summary.by_severity.get("critical", 0)),
                    str(scan.summary.by_severity.get("high", 0)),
                    str(scan.summary.by_severity.get("medium", 0)),
                    str(scan.summary.files_scanned), str(scan.summary.units_scanned),
                ],
            ],
            colWidths=[30 * mm] * 6,
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            ),
        ),
        Spacer(1, 10),
        p("The findings below are review candidates produced by deterministic rules and an optional learned detector. A candidate is not proof of exploitability.", "Small2"),
        p("Findings", "H2v"),
    ]
    for index, finding in enumerate(_active(scan), start=1):
        line = finding.evidence[0].line if finding.evidence else finding.start_line
        story.append(p(f"{index}. {finding.cwe_title} ({finding.cwe}) · {finding.severity.upper()}", "H3v"))
        story.append(p(f"{finding.path}:{line} · {finding.function} · {round(finding.confidence * 100)}% confidence · {finding.engine}", "Small2"))
        for evidence in finding.evidence[:4]:
            story.append(p(f"line {evidence.line}: {mask_text(evidence.snippet)}", "Small2"))
            story.append(p(evidence.reason, "Small2"))
        story.append(p("Remediation", "Small2"))
        for item in (finding.explanation or {}).get("remediation", [])[:5]:
            story.append(p(f"• {item}", "Body2"))
        verified = [c for c in finding.patch_candidates if c.verification != "unverified"]
        if verified:
            patch = verified[0]
            story.append(p(f"Proposed repair ({patch.verification.replace('_', ' ')}): {patch.summary}", "Body2"))
            story.append(p(patch.unified_diff[:4000], "Small2"))
        if index < len(_active(scan)):
            story.append(Spacer(1, 10))
    document.build(story)
    return buffer.getvalue()
