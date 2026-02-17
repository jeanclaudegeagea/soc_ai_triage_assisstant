from typing import Any, Dict, List
import re


class MitreMapper:
    """
    Rule-based MITRE ATT&CK mapper for common SOC web/infra attack patterns.
    """

    # Pattern name -> MITRE technique candidates
    PATTERN_TECHNIQUES = {
        "sql_injection": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": 0.9,
                "reason": "SQL injection attempts target exposed application input vectors.",
            }
        ],
        "xss": [
            {
                "technique_id": "T1059.007",
                "technique_name": "JavaScript",
                "tactic": "Execution",
                "confidence": 0.7,
                "reason": "XSS payloads commonly rely on JavaScript execution in a victim context.",
            },
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": 0.75,
                "reason": "XSS often abuses web application input handling vulnerabilities.",
            },
        ],
        "path_traversal": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": 0.8,
                "reason": "Path traversal commonly exploits insecure web application file handling.",
            },
        ],
        "command_injection": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "confidence": 0.85,
                "reason": "Injected shell/system commands indicate command interpreter abuse.",
            }
        ],
        "brute_force": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.95,
                "reason": "Repeated failed authentications are characteristic brute-force behavior.",
            }
        ],
        "ddos": [
            {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "tactic": "Impact",
                "confidence": 0.9,
                "reason": "High-volume traffic/flooding indicates service availability degradation attempts.",
            }
        ],
        "malware": [
            {
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "tactic": "Execution",
                "confidence": 0.55,
                "reason": "Generic malware indicators often involve user-triggered payload execution.",
            }
        ],
        "data_exfiltration": [
            {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "confidence": 0.7,
                "reason": "Suspicious outbound transfers may indicate data exfiltration over control channels.",
            },
            {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "confidence": 0.65,
                "reason": "Unusual transfer protocols can reflect alternate-path data exfiltration.",
            },
        ],
    }

    KEYWORD_TECHNIQUES = [
        (
            r"(?i)(credential|password spraying|auth.*failed|login.*failed)",
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.75,
                "reason": "Credential abuse keywords indicate brute-force style access attempts.",
            },
        ),
        (
            r"(?i)(powershell|cmd\.exe|/bin/sh|bash -c|wget|curl)",
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "confidence": 0.7,
                "reason": "Command interpreter artifacts suggest script/command execution behavior.",
            },
        ),
        (
            r"(?i)(exfil|large.*outbound|data.*transfer)",
            {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "confidence": 0.6,
                "reason": "Outbound transfer anomalies are consistent with potential data exfiltration.",
            },
        ),
    ]

    def map_attack(
        self, log_entry: str, detected_patterns: List[str], analysis: str = ""
    ) -> List[Dict[str, Any]]:
        techniques: List[Dict[str, Any]] = []

        for pattern in detected_patterns or []:
            techniques.extend(self.PATTERN_TECHNIQUES.get(pattern, []))

        corpus = "\n".join([log_entry or "", analysis or ""])
        for regex, technique in self.KEYWORD_TECHNIQUES:
            if re.search(regex, corpus):
                techniques.append(technique)

        return self._dedupe_and_rank(techniques)

    def map_correlation_group(self, events: List[str]) -> List[Dict[str, Any]]:
        corpus = "\n".join(events or [])
        techniques: List[Dict[str, Any]] = []
        for regex, technique in self.KEYWORD_TECHNIQUES:
            if re.search(regex, corpus):
                techniques.append(technique)
        return self._dedupe_and_rank(techniques)

    def summarize(self, attack_details: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        by_tactic: Dict[str, int] = {}
        details: Dict[str, Dict[str, Any]] = {}

        for attack in attack_details or []:
            for technique in attack.get("mitre_attack", []):
                tid = technique.get("technique_id", "UNKNOWN")
                counts[tid] = counts.get(tid, 0) + 1
                tactic = technique.get("tactic", "Unknown")
                by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
                details[tid] = technique

        top_techniques = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        technique_rows = []
        for tid, count in top_techniques:
            info = details.get(tid, {})
            technique_rows.append(
                {
                    "technique_id": tid,
                    "technique_name": info.get("technique_name", "Unknown"),
                    "tactic": info.get("tactic", "Unknown"),
                    "count": count,
                }
            )

        return {
            "techniques": technique_rows,
            "tactics": by_tactic,
            "mapped_attack_count": sum(counts.values()),
            "unique_technique_count": len(technique_rows),
        }

    def _dedupe_and_rank(
        self, techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for t in techniques:
            tid = t.get("technique_id", "UNKNOWN")
            conf = float(t.get("confidence", 0))
            if tid not in merged or conf > float(merged[tid].get("confidence", 0)):
                merged[tid] = dict(t)

        ordered = sorted(
            merged.values(), key=lambda x: float(x.get("confidence", 0)), reverse=True
        )
        for row in ordered:
            row["confidence"] = round(float(row.get("confidence", 0)) * 100, 1)
        return ordered[:5]
