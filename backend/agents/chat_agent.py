from langchain_core.prompts import PromptTemplate
from agents.base_agent import BaseAgent


class ChatAgent(BaseAgent):
    """
    Agent for answering questions about security logs and reports
    """

    CHAT_PROMPT = """You are a helpful SOC analyst assistant.

Role: {role}

You have access to the following security log analysis:

ORIGINAL LOGS:
{logs}

SECURITY ANALYSIS REPORT:
{report}

User Question: {question}

Provide a clear, concise, and accurate answer based on the logs and analysis report.
If the information is not available in the provided data, say so clearly.
Always cite specific log entries or report sections when answering."""

    def __init__(self, llm):
        super().__init__(llm, "ChatAgent")
        self.prompt = PromptTemplate(
            template=self.CHAT_PROMPT,
            input_variables=["role", "logs", "report", "question"],
        )

    def execute(self, role: str, logs: str, report: str, question: str) -> str:
        """
        Answer questions about logs and analysis

        Args:
            role: Analyst role
            logs: Original log data
            report: Analysis report
            question: User question

        Returns:
            Answer to the question
        """
        self.log_activity(f"Answering question: {question[:50]}...")

        chain = self.prompt | self.llm
        result = chain.invoke(
            {"role": role, "logs": logs, "report": report, "question": question}
        )

        return result.content
