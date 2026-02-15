from typing import Dict, Any, List
from langchain_core.prompts import PromptTemplate
from agents.base_agent import BaseAgent
import re


class AttackDetectionAgent(BaseAgent):
    """
    Agent specialized in detecting and explaining security attacks
    """

    ATTACK_ANALYSIS_PROMPT = """You are a cybersecurity expert specializing in attack pattern recognition.

Analyze the following suspicious log entry and provide detailed analysis:

LOG ENTRY:
{log_entry}

CONTEXT:
{context}

Provide a structured analysis with:

1. **Attack Type**: Identify the specific attack (e.g., SQL Injection, XSS, Brute Force, DDoS, etc.)

2. **Attack Story**: Brief narrative of what happened in this attack attempt

3. **Technical Explanation**: Detailed technical breakdown of the attack mechanism

4. **Potential Impact**: What could happen if this attack succeeds
   - Data compromise
   - System availability
   - Service disruption
   - Lateral movement potential

5. **Defensive Recommendations**: Specific, actionable steps to:
   - Block this attack
   - Prevent future similar attacks
   - Harden the affected system

6. **Severity Level**: Critical / High / Medium / Low

7. **IOCs (Indicators of Compromise)**: Extract relevant IPs, URLs, patterns

Be precise, technical, and actionable."""

    def __init__(self, llm):
        super().__init__(llm, "AttackDetectionAgent")
        self.prompt = PromptTemplate(
            template=self.ATTACK_ANALYSIS_PROMPT,
            input_variables=["log_entry", "context"],
        )

        # Attack pattern signatures
        self.attack_patterns = {
            "sql_injection": [
                r"(?i)(union.*select|select.*from|insert.*into|drop.*table|exec\(|execute\()",
                r"(?i)('.*or.*'|\".*or.*\"|1=1|' or '1'='1)",
            ],
            "xss": [
                r"(?i)(<script|javascript:|onerror=|onload=|<iframe)",
            ],
            "path_traversal": [
                r"(?i)(\.\.\/|\.\.\\|%2e%2e|etc/passwd|windows/system32)",
            ],
            "command_injection": [
                r"(?i)(;\s*(ls|cat|wget|curl|nc|bash|sh)\s|`.*`|\$\(.*\))",
            ],
            "brute_force": [
                r"(?i)(failed.*login|authentication.*failed|invalid.*password).*\d+.*times",
                r"(?i)multiple.*failed.*attempts",
            ],
            "ddos": [
                r"(?i)(flood|ddos|dos attack|rate limit exceeded)",
                r"(?i)connection.*refused.*high.*traffic",
            ],
            "malware": [
                r"(?i)(malware|virus|trojan|ransomware|backdoor|rootkit)",
            ],
            "data_exfiltration": [
                r"(?i)(unusual.*outbound|large.*data.*transfer|exfiltration)",
            ],
        }

    def execute(self, log_entry: str, context: str = "") -> Dict[str, Any]:
        """
        Analyze a log entry for attacks

        Args:
            log_entry: Single log entry to analyze
            context: Additional context information

        Returns:
            Detailed attack analysis
        """
        self.log_activity("Analyzing potential attack in log entry")

        # First, detect attack type
        detected_attacks = self.detect_attack_type(log_entry)

        # Get detailed AI analysis
        chain = self.prompt | self.llm
        result = chain.invoke(
            {
                "log_entry": log_entry,
                "context": f"{context}\nDetected patterns: {', '.join(detected_attacks) if detected_attacks else 'Unknown'}",
            }
        )

        return {
            "log_entry": log_entry,
            "detected_patterns": detected_attacks,
            "analysis": result.content,
        }

    def detect_attack_type(self, log_entry: str) -> List[str]:
        """
        Detect attack types using pattern matching

        Args:
            log_entry: Log entry to check

        Returns:
            List of detected attack types
        """
        detected = []

        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_entry):
                    detected.append(attack_type)
                    break

        return detected

    def batch_analyze(
        self, log_entries: List[str], context: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple log entries for attacks

        Args:
            log_entries: List of log entries
            context: Additional context

        Returns:
            List of attack analyses
        """
        results = []

        for entry in log_entries:
            # Only analyze entries that look suspicious
            if self.detect_attack_type(entry):
                analysis = self.execute(entry, context)
                results.append(analysis)

        return results
