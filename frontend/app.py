import streamlit as st
import requests
import pandas as pd
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
# from reportlab.lib.units import inch


API_BASE = "http://localhost:8000/api/chat"

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

    detected_pattern = st.text_input(
        "Detected pattern (optional)",
        placeholder="e.g. brute force, suspicious login",
    )

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
                    "detected_pattern": detected_pattern or "unknown",
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
# PDF Generator
# -----------------------------
def generate_pdf(report, role):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    x = 40
    y = height - 40

    def draw_text(title, text):
        nonlocal y
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(x, y, title)
        y -= 14
        pdf.setFont("Helvetica", 10)

        for line in str(text).split("\n"):
            if y < 40:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = height - 40
            pdf.drawString(x, y, line)
            y -= 12

        y -= 10

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(x, y, "SOC Security Analysis Report")
    y -= 30

    draw_text("Severity", report["severity"])
    draw_text("Severity Score", report["severity_score"])
    draw_text("Attack Story", report["attack_story"])
    draw_text("Explanation", report["explanation"])
    draw_text("Potential Impact", report["potential_impact"])

    if role.lower() == "ceo":
        draw_text("Estimated Financial Impact", report["estimated_financial_impact"])

    draw_text("Defensive Recommendations", "\n".join(report["recommendations"]))

    if report["cves"]:
        draw_text("Related CVEs", ", ".join(report["cves"]))

    pdf.showPage()
    pdf.save()
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
        label="📄 Download Report as PDF",
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
                        "metrics": report["metrics"],
                    },
                )

                if response.status_code == 200:
                    answer = response.json()["answer"]
                else:
                    answer = "❌ Failed to get response from SOC AI."

                st.markdown(answer)

        st.session_state.messages.append({"role": "assistant", "content": answer})
