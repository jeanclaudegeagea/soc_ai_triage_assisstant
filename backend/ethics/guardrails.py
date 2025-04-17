import re
from fastapi import HTTPException

BLOCKED_INPUT = [
    r"\bnmap\b",
    r"\bmetasploit\b",
    r"\bsqlmap\b",
    r"\breverse shell\b",
    r"\bpayload\b",
]

BLOCKED_OUTPUT = ["run this command", "execute", "step by step attack", "exploit using"]


def check_input_ethics(text: str):
    for p in BLOCKED_INPUT:
        if re.search(p, text, re.IGNORECASE):
            raise HTTPException(
                status_code=400,
                detail="Blocked: exploit or operational content detected",
            )


def sanitize_output(text: str) -> str:
    for phrase in BLOCKED_OUTPUT:
        if phrase in text.lower():
            return "Content removed due to ethical defensive-only policy."
    return text
