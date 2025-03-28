import streamlit as st
import requests
# import json

API_BASE = "http://localhost:8000/api/chat"

st.set_page_config(page_title="SOC AI Analysis Assistant", layout="wide")

st.title("🛡️ SOC AI Analysis Assistant")
st.caption("Ethical • Defensive • Role-Adaptive Security Analysis")

# -----------------------------
# Session State Initialization
# -----------------------------
if "report" not in st.session_state:
    st.session_state.report = None

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# -----------------------------
# Sidebar – Configuration
# -----------------------------
with st.sidebar:
    st.header("⚙️ Configuration")

    role = st.selectbox(
        "Select your role",
        ["junior", "expert", "ceo"],
        help="The explanation and impact will adapt to this role",
    )

    uploaded_file = st.file_uploader("Upload log file", type=["txt", "log", "csv"])

    detected_pattern = st.text_input(
        "Detected pattern (optional)", placeholder="e.g. brute force, suspicious login"
    )

    analyze_clicked = st.button("🔍 Analyze Logs", use_container_width=True)

# -----------------------------
# Read Uploaded Logs
# -----------------------------
logs_content = ""
if uploaded_file:
    logs_content = uploaded_file.read().decode("utf-8", errors="ignore")

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
            st.session_state.chat_history = []
            st.success("Analysis completed successfully.")
        else:
            st.error(response.text)

# -----------------------------
# Display SOC Report
# -----------------------------
if st.session_state.report:
    report = st.session_state.report

    st.subheader("📊 Security Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Severity", report["severity"])
    col2.metric("Severity Score", report["severity_score"])
    col3.metric("CVEs Found", len(report["cves"]))

    st.divider()

    st.subheader("🧠 Attack Story")
    st.write(report["attack_story"])

    st.subheader("📘 Explanation")
    st.write(report["explanation"])

    st.subheader("⚠️ Potential Impact")
    st.write(report["potential_impact"])

    if role == "ceo":
        st.subheader("💰 Estimated Financial Impact")
        st.write(report["estimated_financial_impact"])

    st.subheader("🛠️ Defensive Recommendations")
    for rec in report["recommendations"]:
        st.markdown(f"- {rec}")

    if report["cves"]:
        st.subheader("🧬 Related CVEs")
        st.write(", ".join(report["cves"]))

    st.divider()

    # -----------------------------
    # Chat Section
    # -----------------------------
    st.subheader("💬 Ask Follow-up Questions")

    question = st.text_input(
        "Ask a question about the report or the logs",
        placeholder="What should be our next defensive action?",
    )

    ask_clicked = st.button("Ask", use_container_width=True)

    if ask_clicked and question:
        with st.spinner("Thinking..."):
            chat_response = requests.post(
                f"{API_BASE}/ask",
                json={
                    "role": role,
                    "logs": logs_content,
                    "report": report,
                    "question": question,
                },
            )

        if chat_response.status_code == 200:
            answer = chat_response.json()["answer"]
            st.session_state.chat_history.append(
                {"question": question, "answer": answer}
            )
        else:
            st.error(chat_response.text)

    # -----------------------------
    # Chat History
    # -----------------------------
    if st.session_state.chat_history:
        st.subheader("🗂️ Conversation")
        for chat in st.session_state.chat_history:
            st.markdown(f"**You:** {chat['question']}")
            st.markdown(f"**SOC AI:** {chat['answer']}")
            st.markdown("---")
