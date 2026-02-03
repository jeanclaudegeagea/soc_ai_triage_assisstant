from pydantic import BaseModel
from typing import List, Optional


class AnalyzeRequest(BaseModel):
    role: str
    logs: str
    detected_pattern: Optional[str] = "unknown"


class AnalyzeResponse(BaseModel):
    severity: str
    severity_score: int
    cves: List[str]
    attack_story: str
    explanation: str
    potential_impact: str
    estimated_financial_impact: str
    recommendations: List[str]
    metrics: dict


class AskRequest(BaseModel):
    role: str
    logs: str
    report: dict
    question: str


class AskResponse(BaseModel):
    answer: str
