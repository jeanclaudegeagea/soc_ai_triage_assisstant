import os
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
    return (
        (chat_prompt | llm)
        .invoke({"role": role, "logs": logs, "report": report, "question": question})
        .content
    )
