from typing import Dict, Any
from langchain_core.prompts import PromptTemplate
from agents.base_agent import BaseAgent
import re


class LogAnalysisAgent(BaseAgent):
    """
    Agent responsible for analyzing security logs and identifying patterns
    """
    
    ANALYZE_PROMPT = """You are a SOC (Security Operations Center) analyst expert in log analysis.

Role: {role}

Analyze the following logs for security threats, anomalies, and suspicious patterns:

LOGS:
{logs}

PATTERN TO FOCUS ON: {pattern}

Provide a comprehensive security analysis including:
1. Critical Security Findings (attacks, breaches, intrusions)
2. Severity Assessment (Critical/High/Medium/Low)
3. Attack Patterns Identified
4. Compromised Systems/IPs
5. Recommended Immediate Actions

Be specific and actionable in your analysis."""

    def __init__(self, llm):
        super().__init__(llm, "LogAnalysisAgent")
        self.prompt = PromptTemplate(
            template=self.ANALYZE_PROMPT,
            input_variables=["role", "logs", "pattern"]
        )
    
    def execute(self, role: str, logs: str, pattern: str = "general") -> str:
        """
        Analyze logs for security threats
        
        Args:
            role: Analyst role/context
            logs: Log data to analyze
            pattern: Specific pattern to focus on
            
        Returns:
            Analysis report
        """
        self.log_activity(f"Analyzing logs with pattern: {pattern}")
        
        chain = self.prompt | self.llm
        result = chain.invoke({
            "role": role,
            "logs": logs,
            "pattern": pattern
        })
        
        return result.content
    
    def extract_metrics(self, logs: str) -> Dict[str, Any]:
        """
        Extract key metrics from logs
        
        Args:
            logs: Raw log data
            
        Returns:
            Dictionary containing metrics
        """
        from collections import Counter
        
        ips = Counter()
        events = Counter()
        timestamps = []
        error_lines = []
        attack_lines = []
        
        for line in logs.splitlines():
            # Extract IPs
            ip_match = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", line)
            if ip_match:
                ips[ip_match.group()] += 1
            
            # Categorize events
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ["failed", "error", "denied", "blocked", "rejected"]):
                events["failed"] += 1
                error_lines.append(line)
            elif any(keyword in line_lower for keyword in ["success", "accepted", "allowed"]):
                events["success"] += 1
            else:
                events["other"] += 1
            
            # Detect potential attacks
            if any(keyword in line_lower for keyword in ["attack", "intrusion", "breach", "malware", "exploit", "injection", "xss", "sql"]):
                attack_lines.append(line)
            
            # Extract timestamps
            time_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
            if time_match:
                timestamps.append(time_match.group())
        
        return {
            "top_ips": ips.most_common(10),
            "event_distribution": dict(events),
            "event_count": sum(events.values()),
            "timestamps": timestamps,
            "error_lines": error_lines,
            "attack_lines": attack_lines
        }