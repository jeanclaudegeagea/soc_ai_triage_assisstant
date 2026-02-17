import streamlit as st
import requests
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()


API_BASE = os.getenv("API_URL")

st.set_page_config(page_title="SOC AI Analysis Assistant", layout="wide")

st.title("🛡️ SOC AI Analysis Assistant")
st.caption(
    "Ethical • Defensive • Role-Adaptive Security Analysis • Multi-Agent Powered"
)

# -----------------------------
# Session State
# -----------------------------
if "report" not in st.session_state:
    st.session_state.report = None

if "messages" not in st.session_state:
    st.session_state.messages = []

if "full_analysis" not in st.session_state:
    st.session_state.full_analysis = None

if "report_pdf_bytes" not in st.session_state:
    st.session_state.report_pdf_bytes = None

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
    st.header("⚙️ Configuration")

    role = st.selectbox(
        "Select your role",
        [
            "SOC Analyst",
            "Security Engineer",
            "Incident Responder",
            "Threat Hunter",
            "SOC Manager",
            "Blue Team Lead",
            "CISO",
            "IT Manager",
            "Executive Leadership",
        ],
        index=0,
        help="Analysis and recommendations are adapted to your selected role.",
    )

    uploaded_file = st.file_uploader(
        "Upload log file", type=["txt", "log", "csv"], accept_multiple_files=False
    )

    analyze_clicked = st.button("🔍 Analyze Logs", use_container_width=True)

# -----------------------------
# Read Logs
# -----------------------------
logs_content = ""
if uploaded_file:
    try:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        logs_content = f"\n\n===== FILE: {uploaded_file.name} =====\n{content}"
    except Exception:
        st.warning(f"Could not read file: {uploaded_file.name}")

# -----------------------------
# Analyze Logs - UPDATED FOR MULTI-AGENT BACKEND
# -----------------------------
if analyze_clicked:
    if not logs_content:
        st.error("Please upload a log file first.")
    else:
        with st.spinner("🤖 Multi-Agent Analysis in Progress..."):
            # UPDATED: New endpoint for multi-agent orchestrator
            response = requests.post(
                f"{API_BASE}/analyze",
                json={
                    "logs": logs_content,
                    "role": role,
                },
            )

        if response.status_code == 200:
            result = response.json()

            # Store full analysis for detailed view
            st.session_state.full_analysis = result
            st.session_state.report_pdf_bytes = None

            # Transform for backward compatibility with your PDF generator
            # (Keep your existing report structure)
            st.session_state.report = {
                "severity": result.get("severity", "MEDIUM"),
                "severity_score": result.get("severity_score", 5),
                "attack_story": result.get("analysis_summary", "Analysis completed"),
                "explanation": result.get("analysis_summary", ""),
                "potential_impact": result.get(
                    "potential_impact", "See detailed attack analysis below"
                ),
                "recommendations": result.get(
                    "recommendations", ["Review detailed findings below"]
                ),
                "cves": result.get("cves", []),
                "metrics": result.get("metrics", {}),
            }

            st.session_state.messages = []
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": "✅ Multi-agent analysis completed! Found {} attacks, {} correlation groups. Ask me anything!".format(
                        len(result.get("attack_details", [])),
                        len(result.get("correlation_results", [])),
                    ),
                }
            )

            st.success("✅ Analysis Complete!")
        else:
            st.error(f"Analysis failed: {response.text}")


def fetch_pdf_report(report, role, full_analysis):
    response = requests.post(
        f"{API_BASE}/report/pdf",
        json={
            "role": role,
            "report": report,
            "full_analysis": full_analysis,
            "filename": "soc_detailed_security_report.pdf",
        },
        timeout=120,
    )

    if response.status_code != 200:
        raise RuntimeError(response.text)

    return response.content


# -----------------------------
# Report Summary (KEEP YOUR EXISTING CODE + ENHANCEMENTS)
# -----------------------------
if st.session_state.report:
    report = st.session_state.report
    full_analysis = st.session_state.full_analysis

    st.subheader("📊 Security Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Severity", report["severity"])
    col2.metric("Severity Score", report["severity_score"])
    col3.metric("CVEs Found", len(report["cves"]))
    mitre_summary = (full_analysis or {}).get("mitre_summary", {})
    mitre_techniques = mitre_summary.get("techniques", [])
    if mitre_techniques:
        st.markdown("**MITRE ATT&CK Mapping Summary**")
        for row in mitre_techniques[:8]:
            st.markdown(
                f"- `{row.get('technique_id', 'N/A')}` {row.get('technique_name', 'Unknown')} ({row.get('tactic', 'Unknown')}) x{row.get('count', 0)}"
            )

    # 📄 PDF Download (Generated in backend)
    if st.session_state.report_pdf_bytes is None:
        try:
            st.session_state.report_pdf_bytes = fetch_pdf_report(
                report=report, role=role, full_analysis=full_analysis
            )
        except Exception as e:
            st.error(f"Failed to generate backend PDF report: {e}")

    if st.session_state.report_pdf_bytes:
        st.download_button(
            label="📄 Download Detailed SOC Report (PDF)",
            data=st.session_state.report_pdf_bytes,
            file_name="soc_detailed_security_report.pdf",
            mime="application/pdf",
        )

    # Keep your existing full report expander
    with st.expander("🧠 Full SOC Report", expanded=True):
        st.markdown("**Attack Story**")
        st.write(report["attack_story"])

        st.markdown("**Explanation**")
        st.write(report["explanation"])

        st.markdown("**Potential Impact**")
        st.write(report["potential_impact"])

        st.markdown("**Defensive Recommendations**")
        for rec in report["recommendations"]:
            st.markdown(f"- {rec}")

        if report["cves"]:
            st.markdown("**Related CVEs**")
            st.write(", ".join(report["cves"]))

    # ============ NEW: DETAILED ATTACK ANALYSIS ============
    if full_analysis and "attack_details" in full_analysis:
        attack_details = full_analysis["attack_details"]

        if attack_details:
            st.subheader("🚨 Detailed Attack Analysis")
            st.caption(f"Found {len(attack_details)} suspicious activities")

            for idx, attack in enumerate(attack_details, 1):
                with st.expander(
                    f"🎯 Attack #{idx}: {', '.join(attack.get('detected_patterns', ['Unknown']))}",
                    expanded=False,
                ):
                    # Display the actual log entry
                    st.markdown("**📋 Log Entry:**")
                    st.code(attack["log_entry"], language="log")

                    # Display detected patterns
                    if attack.get("detected_patterns"):
                        st.markdown("**🔍 Detected Patterns:**")
                        st.write(", ".join(attack["detected_patterns"]))

                    mitre_map = attack.get("mitre_attack", [])
                    if mitre_map:
                        st.markdown("**MITRE ATT&CK Mapping:**")
                        for m in mitre_map:
                            st.markdown(
                                f"- `{m.get('technique_id', 'N/A')}` {m.get('technique_name', 'Unknown')} | Tactic: {m.get('tactic', 'Unknown')} | Confidence: {m.get('confidence', 0)}%"
                            )

                    # Display AI analysis
                    st.markdown("**🤖 AI Analysis:**")
                    st.markdown(attack["analysis"])

                    st.divider()

    # ============ NEW: CORRELATION & FALSE POSITIVE DETECTION ============
    if full_analysis and "correlation_results" in full_analysis:
        corr_results = full_analysis["correlation_results"]

        if corr_results:
            st.subheader("Event Correlation & False Positive Detection")

            for idx, corr in enumerate(corr_results, 1):
                fp_check = corr.get("auto_fp_detection", {})
                verdict = (corr.get("verdict") or "").upper()
                confidence = corr.get("confidence", 0)

                if verdict == "FALSE_POSITIVE":
                    st.success(
                        f"Correlation Group #{idx} - FALSE POSITIVE ({confidence}% confidence)"
                    )
                elif verdict == "TRUE_POSITIVE":
                    st.error(
                        f"Correlation Group #{idx} - TRUE POSITIVE ({confidence}% confidence)"
                    )
                else:
                    st.warning(
                        f"Correlation Group #{idx} - REVIEW NEEDED ({confidence}% confidence)"
                    )

                with st.expander(f"View Details - Group #{idx}"):
                    st.markdown(f"**Related Events:** {len(corr.get('events', []))}")
                    st.markdown(f"**Verdict:** `{verdict or 'REVIEW_NEEDED'}`")
                    st.markdown(f"**Confidence:** `{confidence}%`")
                    st.markdown(
                        f"**Attack Campaign:** {corr.get('attack_campaign', 'N/A')}"
                    )

                    st.markdown("**Reasoning:**")
                    st.write(corr.get("reasoning", "N/A"))

                    patterns = fp_check.get("detected_patterns", [])
                    if patterns:
                        st.write("**Auto False-Positive Pattern Matches:**")
                        for p in patterns:
                            st.write(
                                f"- {p.get('name', 'Unknown')}: {p.get('description', 'N/A')}"
                            )

                    recs = corr.get("recommendations", [])
                    if recs:
                        st.markdown("**Recommended Actions:**")
                        for rec in recs:
                            st.markdown(f"- {rec}")

                    corr_mitre = corr.get("mitre_attack", [])
                    if corr_mitre:
                        st.markdown("**MITRE ATT&CK Mapping:**")
                        for m in corr_mitre:
                            st.markdown(
                                f"- `{m.get('technique_id', 'N/A')}` {m.get('technique_name', 'Unknown')} ({m.get('tactic', 'Unknown')})"
                            )

    # -----------------------------
    # 📈 Visual Security Analytics (KEEP YOUR EXISTING CODE)
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
    # ChatGPT-style Chat - UPDATED ENDPOINT
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
                # UPDATED: New endpoint for multi-agent Q&A
                response = requests.post(
                    f"{API_BASE}/ask",
                    json={
                        "role": role,
                        "logs": logs_content[-4000:] if logs_content else "",
                        "report": report,
                        "question": prompt,
                    },
                )

                if response.status_code == 200:
                    answer = response.json()["answer"]
                else:
                    answer = "❌ Failed to get response from SOC AI."

                st.markdown(answer)

        st.session_state.messages.append({"role": "assistant", "content": answer})



