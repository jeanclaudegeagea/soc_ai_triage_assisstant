import os
import json
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from prompts.analyze_prompt import ANALYZE_PROMPT
from prompts.chat_prompt import CHAT_PROMPT
from dotenv import load_dotenv

load_dotenv()

llm = ChatGroq(
    model="llama-3.1-8b-instant", api_key=os.getenv("GROQ_API_KEY"), temperature=0.1
)

analyze_prompt = PromptTemplate(
    template=ANALYZE_PROMPT, input_variables=["role", "logs", "pattern"]
)

chat_prompt = PromptTemplate(
    template=CHAT_PROMPT, input_variables=["role", "logs", "report", "question"]
)


def analyze_logs(role, logs, pattern):
    return (
        (analyze_prompt | llm)
        .invoke({"role": role, "logs": logs, "pattern": pattern})
        .content
    )


def ask_question(role, logs, report, question):
    safe_logs = _truncate_text(str(logs or ""), max_chars=4000)
    safe_report = _compact_report(report)

    return (
        (chat_prompt | llm)
        .invoke(
            {
                "role": role,
                "logs": safe_logs,
                "report": safe_report,
                "question": str(question or ""),
            }
        )
        .content
    )


def _truncate_text(text: str, max_chars: int = 4000) -> str:
    if len(text) <= max_chars:
        return text

    head = int(max_chars * 0.7)
    tail = max_chars - head
    return (
        f"{text[:head]}\n\n[TRUNCATED FOR TOKEN LIMIT]\n\n{text[-tail:]}"
    )


def _compact_report(report) -> str:
    if isinstance(report, dict):
        metrics = report.get("metrics") or {}
        compact = {
            "severity": report.get("severity"),
            "severity_score": report.get("severity_score"),
            "analysis_summary": report.get("analysis_summary")
            or report.get("attack_story")
            or report.get("explanation"),
            "potential_impact": report.get("potential_impact"),
            "recommendations": (report.get("recommendations") or [])[:5],
            "cves": (report.get("cves") or [])[:10],
            "event_count": metrics.get("event_count"),
            "top_ips": (metrics.get("top_ips") or [])[:5],
            "attack_count": len(report.get("attack_details") or []),
            "correlation_count": len(report.get("correlation_results") or []),
        }
        return _truncate_text(json.dumps(compact, ensure_ascii=True), max_chars=2500)

    return _truncate_text(str(report or ""), max_chars=2500)
