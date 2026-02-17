from typing import Dict, Any, List
from langchain_core.prompts import PromptTemplate
from agents.base_agent import BaseAgent
from collections import defaultdict
from datetime import datetime
import re
import json


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
}}

Output rules:
- Return ONLY valid JSON.
- Do not add markdown, prose, or code fences.
- If uncertain, set verdict to FALSE_POSITIVE only with clear evidence; otherwise favor TRUE_POSITIVE with lower confidence and explicit reasoning.
"""

    def __init__(self, llm):
        super().__init__(llm, "CorrelationAgent")
        self.prompt = PromptTemplate(
            template=self.CORRELATION_PROMPT,
            input_variables=[
                "events",
                "time_info",
                "ip_info",
                "pattern_info",
                "system_info",
            ],
        )

        # Known false positive patterns
        self.false_positive_patterns = [
            {
                "name": "health_checks",
                "pattern": r"(?i)(health.*check|monitoring|probe|ping)",
                "description": "Legitimate monitoring activities",
            },
            {
                "name": "scanner_tools",
                "pattern": r"(?i)(nmap|nessus|qualys|vulnerability.*scan)",
                "description": "Authorized security scanning",
            },
            {
                "name": "automated_backups",
                "pattern": r"(?i)(backup|snapshot|replication)",
                "description": "Scheduled backup operations",
            },
        ]

    def execute(
        self, events: List[str], metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
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
        result = chain.invoke(
            {
                "events": "\n".join(events),
                "time_info": time_info,
                "ip_info": ip_info,
                "pattern_info": pattern_info,
                "system_info": system_info,
            }
        )

        raw_analysis = result.content
        parsed = self._extract_json_block(raw_analysis)
        normalized = self._normalize_structured_output(parsed, fp_check, raw_analysis)

        return {
            "events": events,
            "correlation_analysis": raw_analysis,
            "correlation_structured": normalized,
            "verdict": normalized["verdict"],
            "confidence": normalized["confidence"],
            "reasoning": normalized["reasoning"],
            "attack_campaign": normalized["attack_campaign"],
            "recommendations": normalized["recommendations"],
            "auto_fp_detection": fp_check,
            "time_correlation": time_info,
            "ip_correlation": ip_info,
        }

    def _extract_json_block(self, text: str) -> Dict[str, Any]:
        if not text:
            return {}
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return {}
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _normalize_verdict(self, verdict: str) -> str:
        value = (verdict or "").strip().upper().replace(" ", "_")
        if value in ["TRUE_POSITIVE", "TP", "TRUE"]:
            return "TRUE_POSITIVE"
        if value in ["FALSE_POSITIVE", "FP", "FALSE"]:
            return "FALSE_POSITIVE"
        return "REVIEW_NEEDED"

    def _normalize_structured_output(
        self, parsed: Dict[str, Any], fp_check: Dict[str, Any], raw_analysis: str
    ) -> Dict[str, Any]:
        verdict = self._normalize_verdict(str(parsed.get("verdict", "")))

        if verdict == "REVIEW_NEEDED":
            if fp_check.get("likely_false_positive"):
                verdict = "FALSE_POSITIVE"
            elif "TRUE_POSITIVE" in (raw_analysis or "").upper():
                verdict = "TRUE_POSITIVE"
            elif "FALSE_POSITIVE" in (raw_analysis or "").upper():
                verdict = "FALSE_POSITIVE"

        confidence = parsed.get("confidence", 0)
        try:
            confidence = int(float(confidence))
        except Exception:
            confidence = 0
        confidence = max(0, min(100, confidence))

        reasoning = str(parsed.get("reasoning", "")).strip()
        if not reasoning:
            reasoning = "Correlation output did not contain structured reasoning."

        attack_campaign = str(parsed.get("attack_campaign", "")).strip()
        if not attack_campaign:
            attack_campaign = "N/A"

        recommendations = parsed.get("recommendations", [])
        if not isinstance(recommendations, list):
            recommendations = []
        recommendations = [str(item).strip() for item in recommendations if str(item).strip()]

        if not recommendations:
            if verdict == "TRUE_POSITIVE":
                recommendations = [
                    "Escalate this group to incident response for containment and validation.",
                    "Block or rate-limit implicated source IPs after validation.",
                ]
            elif verdict == "FALSE_POSITIVE":
                recommendations = [
                    "Tune detection rules for this benign activity pattern.",
                    "Document this activity as expected in SOC runbooks.",
                ]
            else:
                recommendations = [
                    "Collect additional telemetry before assigning final verdict.",
                ]

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
            "attack_campaign": attack_campaign,
            "recommendations": recommendations,
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
        attack_keywords = [
            "failed",
            "denied",
            "blocked",
            "error",
            "attack",
            "intrusion",
            "malware",
        ]

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
                detected_fps.append(
                    {
                        "name": fp_pattern["name"],
                        "description": fp_pattern["description"],
                    }
                )

        return {
            "likely_false_positive": len(detected_fps) > 0,
            "detected_patterns": detected_fps,
        }

    def group_related_events(
        self, all_events: List[str], window_seconds: int = 60
    ) -> List[List[str]]:
        """
        Group related events based on time proximity and similarity

        Args:
            all_events: All events to group
            window_seconds: Time window for grouping (seconds)

        Returns:
            List of event groups
        """
        if not all_events:
            return []

        # Stage 1: group by source IP
        ip_groups = defaultdict(list)
        for event in all_events:
            ip = self._extract_primary_ip(event) or "unknown"
            ip_groups[ip].append(event)

        grouped: List[List[str]] = []

        # Stage 2: within each IP bucket, split by timestamp proximity
        for ip, events in ip_groups.items():
            if len(events) < 2:
                continue

            if ip == "unknown":
                # Unknown source: keep together only if there are repeated similar signatures
                signature_groups = defaultdict(list)
                for event in events:
                    signature_groups[self._event_signature(event)].append(event)
                grouped.extend(
                    [g for g in signature_groups.values() if len(g) > 1]
                )
                continue

            records = []
            for event in events:
                records.append(
                    {
                        "event": event,
                        "timestamp": self._extract_timestamp(event),
                    }
                )

            with_time = [r for r in records if r["timestamp"] is not None]
            no_time = [r for r in records if r["timestamp"] is None]

            if with_time:
                with_time.sort(key=lambda x: x["timestamp"])
                current_group = [with_time[0]["event"]]
                last_ts = with_time[0]["timestamp"]

                for record in with_time[1:]:
                    delta = (record["timestamp"] - last_ts).total_seconds()
                    if delta <= window_seconds:
                        current_group.append(record["event"])
                    else:
                        if len(current_group) > 1:
                            grouped.append(current_group)
                        current_group = [record["event"]]
                    last_ts = record["timestamp"]

                if len(current_group) > 1:
                    grouped.append(current_group)

            # Add no-timestamp events as a fallback group if repetitive
            if len(no_time) > 1:
                grouped.append([r["event"] for r in no_time])

        # Sort bigger groups first for better prioritization downstream
        grouped.sort(key=lambda g: len(g), reverse=True)
        return grouped

    def _extract_timestamp(self, event: str):
        match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", event)
        if not match:
            return None
        try:
            return datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    def _extract_primary_ip(self, event: str) -> str:
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", event)
        return match.group() if match else ""

    def _event_signature(self, event: str) -> str:
        normalized = event.lower()
        normalized = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", normalized)
        normalized = re.sub(r"\d", "0", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized[:120]
