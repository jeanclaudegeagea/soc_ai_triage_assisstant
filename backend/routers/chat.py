import json
import re
from fastapi import APIRouter, HTTPException
from models import AnalyzeRequest, AnalyzeResponse, AskRequest, AskResponse
from services.llm import analyze_logs, ask_question
from ethics.guardrails import sanitize_output
from services.log_metrics import extract_metrics
# Add at the top of backend/routers/chat.py
from services.orchestrator import SOCOrchestrator
from services.llm import llm

# Initialize orchestrator
orchestrator = SOCOrchestrator(llm)

router = APIRouter()


def extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("Invalid AI JSON output")
    return json.loads(match.group(0))


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    # check_input_ethics(payload.logs)

    raw = analyze_logs(payload.role, payload.logs, payload.detected_pattern)

    try:
        data = extract_json(raw)
        data['metrics'] = extract_metrics(payload.logs)
        return AnalyzeResponse(**data)
    except Exception:
        raise HTTPException(500, "Failed to parse AI response")


@router.post("/ask", response_model=AskResponse)
def ask(payload: AskRequest):
    # check_input_ethics(payload.logs)

    raw = ask_question(payload.role, payload.logs, payload.report, payload.question)

    return AskResponse(answer=sanitize_output(raw))

# Option B example:
@router.post("/analyze")
async def analyze_endpoint(request: dict):
    """Enhanced with multi-agent system"""
    try:
        logs = request.get("logs", "")
        role = request.get("role", "SOC Analyst")
        
        # Use new orchestrator
        results = orchestrator.analyze_logs(
            logs=logs,
            role=role,
            pattern="general"
        )
        
        # Format response to match your old structure
        return {
            "status": "success",
            "severity": "MEDIUM",
            "severity_score": 5,
            "attack_story": results['analysis_summary'],
            "explanation": results['analysis_summary'],
            "potential_impact": "See detailed attack analysis",
            "recommendations": ["Review detailed findings"],
            "cves": [],
            "metrics": results['metrics'],
            "attack_details": results['attack_details'],
            "correlation_results": results['correlation_results']
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}
