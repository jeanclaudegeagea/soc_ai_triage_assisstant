from fastapi import FastAPI
from routers import chat

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
