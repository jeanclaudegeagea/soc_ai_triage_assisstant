from typing import Dict, Any, List
from langchain_core.prompts import PromptTemplate
from agents.base_agent import BaseAgent
from collections import defaultdict
import re


class CorrelationAgent(BaseAgent):
    """
    Agent responsible for correlating events and filtering false positives
    """
    
    CORRELATION_PROMPT = """You are a SOC analyst expert in event correlation and false positive detection.

Analyze the following grouped events and determine if they represent true security threats or false positives:

EVENTS:
{events}

CORRELATION FACTORS:
- Time proximity: {time_info}
- Source IP frequency: {ip_info}
- Event pattern: {pattern_info}
- System context: {system_info}

Determine:
1. Is this a TRUE POSITIVE (real security threat) or FALSE POSITIVE?
2. Confidence Level (0-100%)
3. Reasoning for your determination
4. If TRUE POSITIVE: What is the attack campaign/pattern?
5. Recommendations for handling

Provide structured JSON output:
{{
    "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE",
    "confidence": <0-100>,
    "reasoning": "<detailed explanation>",
    "attack_campaign": "<name if true positive>",
    "recommendations": ["<action1>", "<action2>"]
}}"""

    def __init__(self, llm):
        super().__init__(llm, "CorrelationAgent")
        self.prompt = PromptTemplate(
            template=self.CORRELATION_PROMPT,
            input_variables=["events", "time_info", "ip_info", "pattern_info", "system_info"]
        )
        
        # Known false positive patterns
        self.false_positive_patterns = [
            {
                "name": "health_checks",
                "pattern": r"(?i)(health.*check|monitoring|probe|ping)",
                "description": "Legitimate monitoring activities"
            },
            {
                "name": "scanner_tools",
                "pattern": r"(?i)(nmap|nessus|qualys|vulnerability.*scan)",
                "description": "Authorized security scanning"
            },
            {
                "name": "automated_backups",
                "pattern": r"(?i)(backup|snapshot|replication)",
                "description": "Scheduled backup operations"
            },
        ]
    
    def execute(self, events: List[str], metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Correlate events and detect false positives
        
        Args:
            events: List of related events
            metadata: Additional metadata about events
            
        Returns:
            Correlation analysis result
        """
        self.log_activity(f"Correlating {len(events)} events")
        
        if metadata is None:
            metadata = {}
        
        # Extract correlation factors
        time_info = self._extract_time_correlation(events)
        ip_info = self._extract_ip_correlation(events)
        pattern_info = self._extract_pattern_correlation(events)
        system_info = metadata.get("system_info", "Unknown system")
        
        # Check for known false positive patterns
        fp_check = self._check_false_positive_patterns(events)
        
        # Get AI correlation analysis
        chain = self.prompt | self.llm
        result = chain.invoke({
            "events": "\n".join(events),
            "time_info": time_info,
            "ip_info": ip_info,
            "pattern_info": pattern_info,
            "system_info": system_info
        })
        
        return {
            "events": events,
            "correlation_analysis": result.content,
            "auto_fp_detection": fp_check,
            "time_correlation": time_info,
            "ip_correlation": ip_info
        }
    
    def _extract_time_correlation(self, events: List[str]) -> str:
        """Extract time-based correlation info"""
        timestamps = []
        for event in events:
            match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", event)
            if match:
                timestamps.append(match.group())
        
        if len(timestamps) < 2:
            return "Insufficient timestamp data"
        
        return f"{len(timestamps)} events over time range: {timestamps[0]} to {timestamps[-1]}"
    
    def _extract_ip_correlation(self, events: List[str]) -> str:
        """Extract IP-based correlation info"""
        ips = defaultdict(int)
        for event in events:
            matches = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", event)
            for ip in matches:
                ips[ip] += 1
        
        if not ips:
            return "No IP addresses found"
        
        top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:3]
        return f"Top IPs: {', '.join([f'{ip}({count})' for ip, count in top_ips])}"
    
    def _extract_pattern_correlation(self, events: List[str]) -> str:
        """Extract pattern-based correlation info"""
        keywords = defaultdict(int)
        attack_keywords = ["failed", "denied", "blocked", "error", "attack", "intrusion", "malware"]
        
        for event in events:
            for keyword in attack_keywords:
                if keyword in event.lower():
                    keywords[keyword] += 1
        
        if not keywords:
            return "No specific attack patterns detected"
        
        return f"Pattern keywords: {dict(keywords)}"
    
    def _check_false_positive_patterns(self, events: List[str]) -> Dict[str, Any]:
        """Check events against known false positive patterns"""
        detected_fps = []
        
        combined_events = "\n".join(events)
        
        for fp_pattern in self.false_positive_patterns:
            if re.search(fp_pattern["pattern"], combined_events):
                detected_fps.append({
                    "name": fp_pattern["name"],
                    "description": fp_pattern["description"]
                })
        
        return {
            "likely_false_positive": len(detected_fps) > 0,
            "detected_patterns": detected_fps
        }
    
    def group_related_events(self, all_events: List[str], window_seconds: int = 60) -> List[List[str]]:
        """
        Group related events based on time proximity and similarity
        
        Args:
            all_events: All events to group
            window_seconds: Time window for grouping (seconds)
            
        Returns:
            List of event groups
        """
        # This is a simplified grouping by IP
        # In production, you'd use more sophisticated correlation
        
        ip_groups = defaultdict(list)
        
        for event in all_events:
            ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", event)
            if ip_match:
                ip = ip_match.group()
                ip_groups[ip].append(event)
            else:
                ip_groups["unknown"].append(event)
        
        return [events for events in ip_groups.values() if len(events) > 1]