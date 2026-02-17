import json
import re

# from fastapi import APIRouter, HTTPException
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

# from models import AnalyzeRequest, AnalyzeResponse, AskRequest, AskResponse
from models import AskRequest, AskResponse, PDFReportRequest

# from services.llm import analyze_logs, ask_question
from services.llm import ask_question
from ethics.guardrails import sanitize_output

# from services.log_metrics import extract_metrics
from services.orchestrator import SOCOrchestrator
from services.llm import llm
from services.pdf_report import build_detailed_soc_pdf

orchestrator = SOCOrchestrator(llm)

router = APIRouter()


def extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("Invalid AI JSON output")
    return json.loads(match.group(0))


# @router.post("/analyze", response_model=AnalyzeResponse)
# def analyze(payload: AnalyzeRequest):
#     # check_input_ethics(payload.logs)

#     raw = analyze_logs(payload.role, payload.logs, payload.detected_pattern)

#     try:
#         data = extract_json(raw)
#         data["metrics"] = extract_metrics(payload.logs)
#         return AnalyzeResponse(**data)
#     except Exception:
#         raise HTTPException(500, "Failed to parse AI response")


@router.post("/ask", response_model=AskResponse)
def ask(payload: AskRequest):
    # check_input_ethics(payload.logs)
    try:
        raw = ask_question(payload.role, payload.logs, payload.report, payload.question)
        return AskResponse(answer=sanitize_output(raw))
    except Exception as e:
        message = str(e)
        if "Request too large" in message or "Error code: 413" in message:
            raise HTTPException(
                status_code=413,
                detail="Ask request is too large for the model token limit. Context was reduced; please ask a narrower question if this persists.",
            )
        raise HTTPException(status_code=500, detail=message)


# Option B example:
@router.post("/analyze")
async def analyze_endpoint(request: dict):
    """Enhanced with multi-agent system"""
    try:
        logs = request.get("logs", "")
        role = request.get("role", "SOC Analyst")

        # Use new orchestrator
        results = orchestrator.analyze_logs(logs=logs, role=role, pattern="general")

        # Format response to match your old structure
        return {
            "status": "success",
            "severity": results["severity"],
            "severity_score": results["severity_score"],
            "attack_story": results["analysis_summary"],
            "explanation": results["analysis_summary"],
            "potential_impact": results["potential_impact"],
            "recommendations": results["recommendations"],
            "cves": results["cves"],
            "metrics": results["metrics"],
            "attack_details": results["attack_details"],
            "correlation_results": results["correlation_results"],
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/report/pdf")
async def generate_pdf_report(payload: PDFReportRequest):
    try:
        pdf_buffer = build_detailed_soc_pdf(
            report=payload.report,
            role=payload.role,
            full_analysis=payload.full_analysis,
        )
        filename = payload.filename or "soc_detailed_security_report.pdf"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers=headers,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {e}")
