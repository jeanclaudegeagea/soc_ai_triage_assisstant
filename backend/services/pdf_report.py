from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List
from xml.sax.saxutils import escape
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _severity_color(severity: str):
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return colors.HexColor("#8B0000")
    if sev == "HIGH":
        return colors.HexColor("#e74c3c")
    if sev == "MEDIUM":
        return colors.HexColor("#f39c12")
    return colors.HexColor("#27ae60")


def _safe_lines(text: str) -> str:
    if not text:
        return "N/A"
    return "<br/>".join(
        _format_inline_markdown(line) for line in text.splitlines() if line.strip()
    ) or "N/A"


def _format_inline_markdown(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"__(.+?)__", r"<b>\1</b>", escaped)
    return escaped


def _parse_corr_verdict(corr: Dict[str, Any]) -> str:
    auto_fp = corr.get("auto_fp_detection", {}).get("likely_false_positive", False)
    analysis = (corr.get("correlation_analysis") or "").upper()
    if auto_fp or "FALSE_POSITIVE" in analysis:
        return "FALSE POSITIVE"
    if "TRUE_POSITIVE" in analysis:
        return "TRUE POSITIVE"
    return "REVIEW NEEDED"


def build_detailed_soc_pdf(
    report: Dict[str, Any], role: str = "SOC Analyst", full_analysis: Dict[str, Any] | None = None
) -> BytesIO:
    full_analysis = full_analysis or {}
    metrics = full_analysis.get("metrics") or report.get("metrics") or {}
    attack_details: List[Dict[str, Any]] = full_analysis.get("attack_details") or []
    correlation_results: List[Dict[str, Any]] = full_analysis.get("correlation_results") or []
    cves: List[str] = report.get("cves") or []
    recommendations: List[str] = report.get("recommendations") or []

    report_generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = report.get("severity", "MEDIUM")
    severity_score = report.get("severity_score", 0)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=40,
        bottomMargin=40,
    )
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_CENTER,
        spaceAfter=10,
    )
    h_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0f3460"),
        spaceBefore=8,
        spaceAfter=8,
    )
    subh_style = ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#1f2937"),
        spaceBefore=6,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#111827"),
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=body_style,
        fontName="Courier",
        fontSize=8,
        leading=10,
    )

    # Cover
    elements.append(Spacer(1, 1.2 * inch))
    elements.append(Paragraph("SECURITY OPERATIONS CENTER", title_style))
    elements.append(Paragraph("DETAILED INCIDENT TRIAGE REPORT", title_style))
    elements.append(Spacer(1, 0.35 * inch))

    sev_table = Table(
        [[Paragraph(f"<b>SEVERITY: {escape(str(severity).upper())}</b>", ParagraphStyle("Sev", parent=body_style, textColor=colors.white, alignment=TA_CENTER, fontSize=13))]],
        colWidths=[4.8 * inch],
    )
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _severity_color(severity)),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    elements.append(sev_table)
    elements.append(Spacer(1, 0.3 * inch))

    meta_data = [
        ["Generated At", report_generated],
        ["Analyst Role", role or "SOC Analyst"],
        ["Severity Score", str(severity_score)],
        ["Total Events", str(metrics.get("event_count", 0))],
        ["Suspicious Entries", str(len(set((metrics.get("error_lines") or []) + (metrics.get("attack_lines") or []))))],
        ["Detected Attacks", str(len(attack_details))],
        ["Correlation Groups", str(len(correlation_results))],
        ["CVEs Referenced", str(len(cves))],
    ]
    meta_table = Table(meta_data, colWidths=[2.0 * inch, 4.0 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(meta_table)
    elements.append(PageBreak())

    # Executive summary
    elements.append(Paragraph("1. Executive Summary", h_style))
    elements.append(Paragraph("<b>Attack Narrative</b>", subh_style))
    elements.append(Paragraph(_safe_lines(report.get("attack_story", "")), body_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph("<b>Technical Explanation</b>", subh_style))
    elements.append(Paragraph(_safe_lines(report.get("explanation", "")), body_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph("<b>Potential Impact</b>", subh_style))
    elements.append(Paragraph(_safe_lines(report.get("potential_impact", "")), body_style))

    # Metrics
    elements.append(Paragraph("2. Metrics and Traffic Profile", h_style))
    dist = metrics.get("event_distribution") or {}
    dist_rows = [["Type", "Count"]] + [[k, str(v)] for k, v in dist.items()]
    if len(dist_rows) == 1:
        dist_rows.append(["N/A", "0"])
    dist_table = Table(dist_rows, colWidths=[3.0 * inch, 1.2 * inch])
    dist_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    elements.append(dist_table)
    elements.append(Spacer(1, 0.12 * inch))

    top_ips = metrics.get("top_ips") or []
    ip_rows = [["Source IP", "Events"]] + [[str(ip), str(count)] for ip, count in top_ips[:10]]
    if len(ip_rows) == 1:
        ip_rows.append(["N/A", "0"])
    ip_table = Table(ip_rows, colWidths=[3.0 * inch, 1.2 * inch])
    ip_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    elements.append(ip_table)
    elements.append(PageBreak())

    # Attack findings
    elements.append(Paragraph("3. Detailed Attack Findings", h_style))
    if not attack_details:
        elements.append(Paragraph("No suspicious attack entries were generated by the analysis pipeline.", body_style))
    else:
        for idx, attack in enumerate(attack_details, start=1):
            elements.append(Paragraph(f"<b>3.{idx} Attack Entry</b>", subh_style))
            patterns = ", ".join(attack.get("detected_patterns") or ["Unknown"])
            elements.append(Paragraph(f"<b>Detected Patterns:</b> {escape(patterns)}", body_style))
            elements.append(Paragraph("<b>Log Entry</b>", body_style))
            elements.append(Paragraph(_safe_lines(str(attack.get("log_entry", "N/A"))), mono_style))
            elements.append(Paragraph("<b>AI Analysis</b>", body_style))
            elements.append(Paragraph(_safe_lines(str(attack.get("analysis", "N/A"))), body_style))
            elements.append(Spacer(1, 0.08 * inch))
            if idx % 3 == 0 and idx < len(attack_details):
                elements.append(PageBreak())

    # Correlation
    elements.append(Paragraph("4. Correlation and False Positive Review", h_style))
    if not correlation_results:
        elements.append(Paragraph("No correlation groups were generated.", body_style))
    else:
        for idx, corr in enumerate(correlation_results, start=1):
            verdict = _parse_corr_verdict(corr)
            verdict_color = (
                colors.HexColor("#b91c1c")
                if verdict == "TRUE POSITIVE"
                else colors.HexColor("#047857")
                if verdict == "FALSE POSITIVE"
                else colors.HexColor("#92400e")
            )
            elements.append(Paragraph(f"<b>4.{idx} Correlation Group</b>", subh_style))
            elements.append(
                Paragraph(
                    f"<b>Verdict:</b> <font color='{verdict_color.hexval()}'>{escape(verdict)}</font>",
                    body_style,
                )
            )
            elements.append(Paragraph(f"<b>Related Events:</b> {len(corr.get('events', []))}", body_style))
            elements.append(Paragraph(f"<b>Time Correlation:</b> {escape(str(corr.get('time_correlation', 'N/A')))}", body_style))
            elements.append(Paragraph(f"<b>IP Correlation:</b> {escape(str(corr.get('ip_correlation', 'N/A')))}", body_style))
            fp_patterns = corr.get("auto_fp_detection", {}).get("detected_patterns", [])
            if fp_patterns:
                formatted = ", ".join([f"{p.get('name', 'unknown')}: {p.get('description', '')}" for p in fp_patterns])
                elements.append(Paragraph(f"<b>False Positive Patterns:</b> {escape(formatted)}", body_style))
            elements.append(Paragraph("<b>Correlation Analysis</b>", body_style))
            elements.append(Paragraph(_safe_lines(str(corr.get("correlation_analysis", "N/A"))), body_style))
            elements.append(Spacer(1, 0.08 * inch))

    elements.append(PageBreak())

    # Response plan and CVEs
    elements.append(Paragraph("5. Recommended Response Plan", h_style))
    if recommendations:
        plan_rows = [["#", "Recommended Action"]] + [
            [str(i), Paragraph(_format_inline_markdown(str(rec)), body_style)]
            for i, rec in enumerate(recommendations, start=1)
        ]
    else:
        plan_rows = [
            ["#", "Recommended Action"],
            ["1", Paragraph("Review findings and align detection rules with SOC runbooks.", body_style)],
        ]
    plan_table = Table(plan_rows, colWidths=[0.5 * inch, 5.5 * inch])
    plan_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    elements.append(plan_table)
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph("6. CVE References", h_style))

    if cves:
        cve_rows = [["CVE ID"]] + [[escape(cve)] for cve in cves]
        cve_table = Table(cve_rows, colWidths=[3.0 * inch])
        cve_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(cve_table)
    else:
        elements.append(Paragraph("No CVE references were extracted from the generated analysis.", body_style))

    # Appendix
    elements.append(PageBreak())
    elements.append(Paragraph("Appendix A: Suspicious Log Snippets", h_style))
    suspicious = list(dict.fromkeys((metrics.get("error_lines") or []) + (metrics.get("attack_lines") or [])))[:40]
    if suspicious:
        for idx, line in enumerate(suspicious, start=1):
            elements.append(Paragraph(f"<b>A.{idx}</b> {escape(line)}", mono_style))
            if idx % 18 == 0 and idx < len(suspicious):
                elements.append(PageBreak())
    else:
        elements.append(Paragraph("No suspicious snippets available.", body_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer
