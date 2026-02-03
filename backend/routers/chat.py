import json
import re
from fastapi import APIRouter, HTTPException
from models import AnalyzeRequest, AnalyzeResponse, AskRequest, AskResponse
from services.llm import analyze_logs, ask_question
from ethics.guardrails import sanitize_output
from services.log_metrics import extract_metrics

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
