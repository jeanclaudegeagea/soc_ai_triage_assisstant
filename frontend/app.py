import streamlit as st
import requests
import pandas as pd
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
)
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()


API_BASE = os.getenv("API_URL")

st.set_page_config(page_title="SOC AI Analysis Assistant", layout="wide")

st.title("🛡️ SOC AI Analysis Assistant")
st.caption("Ethical • Defensive • Role-Adaptive Security Analysis")

# -----------------------------
# Session State
# -----------------------------
if "report" not in st.session_state:
    st.session_state.report = None

if "messages" not in st.session_state:
    st.session_state.messages = []

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
    st.header("⚙️ Configuration")

    role = st.text_input(
        "Select your role",
        placeholder="Explanation adapts to this role",
    )

    uploaded_files = st.file_uploader(
        "Upload log files", type=["txt", "log", "csv"], accept_multiple_files=True
    )

    # detected_pattern = st.text_input(
    #     "Detected pattern (optional)",
    #     placeholder="e.g. brute force, suspicious login",
    # )

    analyze_clicked = st.button("🔍 Analyze Logs", use_container_width=True)

# -----------------------------
# Read Logs
# -----------------------------
logs_content = ""
if uploaded_files:
    combined_logs = []

    for file in uploaded_files:
        try:
            content = file.read().decode("utf-8", errors="ignore")
            combined_logs.append(f"\n\n===== FILE: {file.name} =====\n{content}")
        except Exception:
            st.warning(f"Could not read file: {file.name}")

    logs_content = "\n".join(combined_logs)

# -----------------------------
# Analyze Logs
# -----------------------------
if analyze_clicked:
    if not logs_content:
        st.error("Please upload a log file first.")
    else:
        with st.spinner("Analyzing logs..."):
            response = requests.post(
                f"{API_BASE}/analyze",
                json={
                    "role": role,
                    "logs": logs_content,
                    # "detected_pattern": detected_pattern or "unknown",
                },
            )

        if response.status_code == 200:
            st.session_state.report = response.json()
            st.session_state.messages = []

            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": "✅ Analysis completed. Ask me anything about the logs or the report.",
                }
            )
        else:
            st.error(response.text)


# -----------------------------
# Professional PDF Generator
# -----------------------------
def generate_pdf(report, role):
    """Generate a professional SOC security report PDF"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=60,
    )

    # Container for PDF elements
    elements = []

    # Define styles
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#0f3460"),
        spaceAfter=12,
        spaceBefore=12,
        fontName="Helvetica-Bold",
        borderColor=colors.HexColor("#e94560"),
        borderWidth=0,
        borderPadding=5,
        leftIndent=0,
    )

    subheading_style = ParagraphStyle(
        "CustomSubHeading",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=colors.HexColor("#16213e"),
        spaceAfter=8,
        spaceBefore=8,
        fontName="Helvetica-Bold",
    )

    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontSize=10,
        textColor=colors.HexColor("#2a2a2a"),
        spaceAfter=10,
        alignment=TA_LEFT,
        leading=14,
    )

    # ==================== COVER PAGE ====================

    # Add some space from top
    elements.append(Spacer(1, 1.5 * inch))

    # Title
    title = Paragraph("SECURITY OPERATIONS CENTER", title_style)
    elements.append(title)
    elements.append(Spacer(1, 0.1 * inch))

    subtitle = Paragraph("THREAT ANALYSIS REPORT", title_style)
    elements.append(subtitle)
    elements.append(Spacer(1, 0.5 * inch))

    # Severity Box
    severity_color = colors.HexColor("#27ae60")  # Green
    if report["severity"].upper() == "HIGH":
        severity_color = colors.HexColor("#e74c3c")  # Red
    elif report["severity"].upper() == "MEDIUM":
        severity_color = colors.HexColor("#f39c12")  # Orange
    elif report["severity"].upper() == "CRITICAL":
        severity_color = colors.HexColor("#8B0000")  # Dark Red

    severity_data = [
        [
            Paragraph(
                f"<b>SEVERITY: {report['severity'].upper()}</b>",
                ParagraphStyle(
                    "SevText",
                    parent=body_style,
                    fontSize=16,
                    textColor=colors.white,
                    alignment=TA_CENTER,
                ),
            )
        ]
    ]

    severity_table = Table(severity_data, colWidths=[4 * inch])
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), severity_color),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 15),
                ("GRID", (0, 0), (-1, -1), 2, colors.white),
            ]
        )
    )
    elements.append(severity_table)
    elements.append(Spacer(1, 0.5 * inch))

    # Report metadata table
    metadata = [
        ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Analyst Role:", role.title() if role else "Security Analyst"],
        ["Severity Score:", str(report["severity_score"])],
        ["CVEs Identified:", str(len(report["cves"])) if report["cves"] else "0"],
    ]

    meta_table = Table(metadata, colWidths=[2 * inch, 3 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#2c3e50")),
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    elements.append(meta_table)

    elements.append(Spacer(1, 1 * inch))

    # Footer on cover page
    footer_text = Paragraph(
        "<i>CONFIDENTIAL - For Internal Security Use Only</i>",
        ParagraphStyle(
            "Footer",
            parent=body_style,
            fontSize=9,
            textColor=colors.grey,
            alignment=TA_CENTER,
        ),
    )
    elements.append(footer_text)

    # Page break
    elements.append(PageBreak())

    # ==================== EXECUTIVE SUMMARY ====================

    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Attack Story Section
    elements.append(Paragraph("Attack Narrative", subheading_style))
    attack_story_text = report["attack_story"].replace("\n", "<br/>")
    elements.append(Paragraph(attack_story_text, body_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Potential Impact
    elements.append(Paragraph("Potential Impact", subheading_style))
    impact_text = report["potential_impact"].replace("\n", "<br/>")
    elements.append(Paragraph(impact_text, body_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Financial Impact (if CEO)
    if role.lower() == "ceo" and "estimated_financial_impact" in report:
        elements.append(Paragraph("Estimated Financial Impact", subheading_style))
        financial_text = report["estimated_financial_impact"].replace("\n", "<br/>")
        elements.append(Paragraph(financial_text, body_style))
        elements.append(Spacer(1, 0.2 * inch))

    elements.append(PageBreak())

    # ==================== TECHNICAL ANALYSIS ====================

    elements.append(Paragraph("TECHNICAL ANALYSIS", heading_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Detailed Explanation
    elements.append(Paragraph("Detailed Technical Explanation", subheading_style))
    explanation_text = report["explanation"].replace("\n", "<br/>")
    elements.append(Paragraph(explanation_text, body_style))
    elements.append(Spacer(1, 0.3 * inch))

    # CVEs Section (if available)
    if report["cves"]:
        elements.append(Paragraph("Related CVE References", subheading_style))

        cve_data = [["CVE ID", "Status"]]
        for cve in report["cves"]:
            cve_data.append([cve, "Identified"])

        cve_table = Table(cve_data, colWidths=[3 * inch, 2 * inch])
        cve_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 11),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8f9fa")],
                    ),
                ]
            )
        )
        elements.append(cve_table)
        elements.append(Spacer(1, 0.3 * inch))

    elements.append(PageBreak())

    # ==================== RECOMMENDATIONS ====================

    elements.append(Paragraph("DEFENSIVE RECOMMENDATIONS", heading_style))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(
        Paragraph(
            "The following defensive measures are recommended to mitigate the identified threats:",
            body_style,
        )
    )
    elements.append(Spacer(1, 0.1 * inch))

    # Recommendations table
    rec_data = [["#", "Recommendation", "Priority"]]

    for idx, rec in enumerate(report["recommendations"], 1):
        # Determine priority based on severity
        if report["severity"].upper() in ["CRITICAL", "HIGH"]:
            priority = "HIGH"
            priority_color = colors.HexColor("#e74c3c")
        elif report["severity"].upper() == "MEDIUM":
            priority = "MEDIUM"
            priority_color = colors.HexColor("#f39c12")
        else:
            priority = "LOW"
            priority_color = colors.HexColor("#27ae60")

        rec_data.append(
            [
                str(idx),
                Paragraph(rec, body_style),
                Paragraph(
                    f"<b>{priority}</b>",
                    ParagraphStyle(
                        "Priority",
                        parent=body_style,
                        textColor=priority_color,
                        alignment=TA_CENTER,
                    ),
                ),
            ]
        )

    rec_table = Table(rec_data, colWidths=[0.5 * inch, 3.8 * inch, 1 * inch])
    rec_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("ALIGN", (2, 0), (2, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("TOPPADDING", (0, 1), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f8f9fa")],
                ),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    elements.append(rec_table)

    elements.append(Spacer(1, 0.5 * inch))

    # ==================== FOOTER ====================

    elements.append(Spacer(1, 0.5 * inch))

    footer_data = [
        [
            Paragraph(
                "<i>This report is confidential and intended for authorized personnel only.</i>",
                ParagraphStyle(
                    "FooterText",
                    parent=body_style,
                    fontSize=8,
                    textColor=colors.grey,
                    alignment=TA_CENTER,
                ),
            )
        ]
    ]

    footer_table = Table(footer_data, colWidths=[6 * inch])
    footer_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    elements.append(footer_table)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer


# -----------------------------
# Report Summary
# -----------------------------
if st.session_state.report:
    report = st.session_state.report

    st.subheader("📊 Security Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Severity", report["severity"])
    col2.metric("Severity Score", report["severity_score"])
    col3.metric("CVEs Found", len(report["cves"]))

    # 📄 PDF Download
    pdf_buffer = generate_pdf(report, role)
    st.download_button(
        label="📄 Download Professional SOC Report (PDF)",
        data=pdf_buffer,
        file_name="soc_security_report.pdf",
        mime="application/pdf",
    )

    with st.expander("🧠 Full SOC Report", expanded=True):
        st.markdown("**Attack Story**")
        st.write(report["attack_story"])

        st.markdown("**Explanation**")
        st.write(report["explanation"])

        st.markdown("**Potential Impact**")
        st.write(report["potential_impact"])

        if role.lower() == "ceo":
            st.markdown("**Estimated Financial Impact**")
            st.write(report["estimated_financial_impact"])

        st.markdown("**Defensive Recommendations**")
        for rec in report["recommendations"]:
            st.markdown(f"- {rec}")

        if report["cves"]:
            st.markdown("**Related CVEs**")
            st.write(", ".join(report["cves"]))

    # -----------------------------
    # 📈 Visual Security Analytics
    # -----------------------------
    if "metrics" in report:
        metrics = report["metrics"]

        st.subheader("📈 Security Visual Analytics")

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("**Event Distribution**")
            if metrics.get("event_distribution"):
                st.bar_chart(metrics["event_distribution"])
            else:
                st.info("No event distribution data available.")

        with col_b:
            st.markdown("**Top Source IPs**")
            if metrics.get("top_ips"):
                st.bar_chart(dict(metrics["top_ips"]))
            else:
                st.info("No IP data available.")

        if metrics.get("timestamps"):
            st.markdown("**Events Over Time**")
            df = pd.DataFrame(metrics["timestamps"], columns=["timestamp"])
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna()
            timeline = df.groupby(df["timestamp"].dt.floor("min")).size()
            st.line_chart(timeline)

    st.divider()

    # -----------------------------
    # ChatGPT-style Chat
    # -----------------------------
    st.subheader("💬 SOC AI Chat")

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    prompt = st.chat_input("Ask about the logs, impact, or next defensive steps...")

    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("SOC AI is thinking..."):
                response = requests.post(
                    f"{API_BASE}/ask",
                    json={
                        "role": role,
                        "logs": logs_content,
                        "report": report,
                        "question": prompt,
                        "metrics": report.get("metrics", {}),
                    },
                )

                if response.status_code == 200:
                    answer = response.json()["answer"]
                else:
                    answer = "❌ Failed to get response from SOC AI."

                st.markdown(answer)

        st.session_state.messages.append({"role": "assistant", "content": answer})
