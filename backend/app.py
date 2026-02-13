from fastapi import FastAPI
from routers import chat
# At the top of backend/app.py, add this import:
from services.orchestrator import SOCOrchestrator
from services.llm import llm  # Your existing LLM instance

# After your app initialization, add:
orchestrator = SOCOrchestrator(llm)

app = FastAPI(
    title="SOC AI Triage Assistant",
    description=(
        "Ethical AI-powered SOC assistant for defensive log analysis. "
        "Supports role-based explanations (Junior, Expert, CEO) and "
        "continuous SOC-oriented conversations."
    ),
    version="1.0.0",
)

# Register API routes
app.include_router(chat.router, prefix="/api/chat", tags=["SOC AI"])


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "service": "SOC AI Triage Assistant",
        "mode": "defensive-only",
        "ethics": "enabled",
    }
# Add these NEW endpoints:

@app.post("/api/analyze-logs")
async def analyze_logs_endpoint(request: dict):
    """
    Multi-agent comprehensive log analysis
    """
    try:
        logs = request.get("logs", "")
        role = request.get("role", "SOC Analyst")
        pattern = request.get("pattern", "general")
        
        if not logs:
            return {"status": "error", "message": "No logs provided"}
        
        # Use orchestrator for comprehensive analysis
        results = orchestrator.analyze_logs(
            logs=logs,
            role=role,
            pattern=pattern
        )
        
        return {
            "status": "success",
            "analysis_summary": results['analysis_summary'],
            "metrics": results['metrics'],
            "attack_details": results['attack_details'],
            "correlation_results": results['correlation_results'],
            "report": results['report'],
            "severity": "MEDIUM",  # You can calculate this from results
            "severity_score": 5,
            "cves": [],
            "recommendations": ["Review detailed findings"],
            "attack_story": results['analysis_summary'],
            "explanation": results['analysis_summary'],
            "potential_impact": "See detailed attack analysis"
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/ask-question")
async def ask_question_endpoint(request: dict):
    """
    Ask questions about analyzed logs
    """
    try:
        logs = request.get("logs", "")
        report = request.get("report", "")
        question = request.get("question", "")
        
        if not all([logs, report, question]):
            return {"status": "error", "message": "Missing required fields"}
        
        answer = orchestrator.ask_question(
            logs=logs,
            report=report,
            question=question
        )
        
        return {
            "status": "success",
            "answer": answer
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}
