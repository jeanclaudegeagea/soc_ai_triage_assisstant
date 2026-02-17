from typing import Dict, Any, List, Tuple
import json
import re
from agents import (
    LogAnalysisAgent,
    AttackDetectionAgent,
    CorrelationAgent,
    ChatAgent,
    ReportGenerationAgent,
)
from services.mitre_mapper import MitreMapper


class SOCOrchestrator:
    """
    Main orchestrator that coordinates all agents for complete security analysis
    """

    def __init__(self, llm):
        """
        Initialize orchestrator with all agents

        Args:
            llm: Language model instance
        """
        self.llm = llm

        # Initialize all agents
        self.log_analysis_agent = LogAnalysisAgent(llm)
        self.attack_detection_agent = AttackDetectionAgent(llm)
        self.correlation_agent = CorrelationAgent(llm)
        self.chat_agent = ChatAgent(llm)
        self.report_agent = ReportGenerationAgent(llm)
        self.mitre_mapper = MitreMapper()

        print("[Orchestrator] All agents initialized")

    def analyze_logs(
        self, logs: str, role: str = "SOC Analyst", pattern: str = "general"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive log analysis using all agents

        Args:
            logs: Raw log data
            role: Analyst role/context
            pattern: Specific pattern to focus on

        Returns:
            Complete analysis results
        """
        print("\n" + "=" * 80)
        print("STARTING COMPREHENSIVE SECURITY ANALYSIS")
        print("=" * 80 + "\n")

        results = {}

        # Step 1: Extract metrics and basic analysis
        print("📊 Step 1: Extracting metrics and performing initial analysis...")
        metrics = self.log_analysis_agent.extract_metrics(logs)
        analysis_summary = self.log_analysis_agent.execute(role, logs, pattern)

        results["metrics"] = metrics
        results["analysis_summary"] = analysis_summary

        print(f"   ✓ Found {metrics['event_count']} total events")
        print(f"   ✓ Identified {len(metrics['error_lines'])} error/suspicious events")
        print(
            f"   ✓ Detected {len(metrics['attack_lines'])} potential attack indicators"
        )

        # Step 2: Detailed attack analysis
        print("\n🔍 Step 2: Performing detailed attack analysis...")
        attack_details = []

        # Analyze error lines and attack lines
        suspicious_logs = list(set(metrics["error_lines"] + metrics["attack_lines"]))

        if suspicious_logs:
            attack_details = self.attack_detection_agent.batch_analyze(
                suspicious_logs[:20],  # Limit to top 20 to avoid overload
                context=f"Total events: {metrics['event_count']}",
            )
            print(f"   ✓ Analyzed {len(attack_details)} suspicious log entries")
        else:
            print("   ℹ No suspicious log entries detected")

        for attack in attack_details:
            attack["mitre_attack"] = self.mitre_mapper.map_attack(
                log_entry=attack.get("log_entry", ""),
                detected_patterns=attack.get("detected_patterns", []),
                analysis=attack.get("analysis", ""),
            )

        results["attack_details"] = attack_details

        # Step 3: Correlation and false positive detection
        print("\n🔗 Step 3: Correlating events and detecting false positives...")
        correlation_results = []

        if suspicious_logs:
            # Group related events
            event_groups = self.correlation_agent.group_related_events(
                suspicious_logs, window_seconds=300
            )

            print(f"   ✓ Identified {len(event_groups)} correlation groups")

            # Analyze each group
            for group in event_groups[:10]:  # Limit to top 10 groups
                corr_result = self.correlation_agent.execute(
                    group, metadata={"system_info": "Production environment"}
                )
                corr_result["mitre_attack"] = self.mitre_mapper.map_correlation_group(
                    corr_result.get("events", [])
                )
                correlation_results.append(corr_result)

            # Count false positives
            fp_count = sum(
                1
                for cr in correlation_results
                if cr.get("auto_fp_detection", {}).get("likely_false_positive")
            )
            print(f"   ✓ Detected {fp_count} likely false positives")

        results["correlation_results"] = correlation_results

        # Step 3.5: Derive triage metadata for API responses
        severity, severity_score = self._estimate_severity(
            metrics=metrics,
            attack_details=attack_details,
            correlation_results=correlation_results,
        )
        recommendations = self._extract_recommendations(
            attack_details=attack_details, correlation_results=correlation_results
        )
        cves = self._extract_cves(analysis_summary, attack_details)
        potential_impact = self._derive_potential_impact(
            attack_details, analysis_summary
        )

        results["severity"] = severity
        results["severity_score"] = severity_score
        results["recommendations"] = recommendations
        results["cves"] = cves
        results["potential_impact"] = potential_impact
        results["mitre_summary"] = self.mitre_mapper.summarize(attack_details)

        # Step 4: Generate comprehensive report
        print("\n📄 Step 4: Generating comprehensive security report...")
        report = self.report_agent.execute(
            analysis_summary=analysis_summary,
            attack_details=attack_details,
            correlation_results=correlation_results,
            metrics=metrics,
        )

        results["report"] = report
        print("   ✓ Report generated successfully")

        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETE")
        print("=" * 80 + "\n")

        return results

    def _estimate_severity(
        self,
        metrics: Dict[str, Any],
        attack_details: List[Dict[str, Any]],
        correlation_results: List[Dict[str, Any]],
    ) -> Tuple[str, int]:
        suspicious_count = len(
            set(metrics.get("error_lines", []) + metrics.get("attack_lines", []))
        )
        attack_count = len(attack_details)
        true_positive_groups = 0
        false_positive_groups = 0

        for corr in correlation_results:
            corr_text = (corr.get("correlation_analysis") or "").upper()
            verdict = (
                str(corr.get("verdict") or "")
                or str((corr.get("correlation_structured") or {}).get("verdict") or "")
            ).upper()
            auto_fp = corr.get("auto_fp_detection", {}).get(
                "likely_false_positive", False
            )

            if "TRUE_POSITIVE" in verdict or "TRUE_POSITIVE" in corr_text:
                true_positive_groups += 1
            if "FALSE_POSITIVE" in verdict or "FALSE_POSITIVE" in corr_text or auto_fp:
                false_positive_groups += 1

        score = min(
            100,
            max(
                0,
                suspicious_count * 3
                + attack_count * 12
                + true_positive_groups * 10
                - false_positive_groups * 6,
            ),
        )

        if score >= 80:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        return severity, score

    def _extract_recommendations(
        self,
        attack_details: List[Dict[str, Any]],
        correlation_results: List[Dict[str, Any]],
    ) -> List[str]:
        recs: List[str] = []

        for attack in attack_details:
            recs.extend(
                self._parse_recommendations_from_text(attack.get("analysis", ""))
            )

        for corr in correlation_results:
            struct = corr.get("correlation_structured", {})
            direct_recs = corr.get("recommendations", [])
            if isinstance(direct_recs, list):
                recs.extend(
                    [str(item).strip() for item in direct_recs if str(item).strip()]
                )
            struct_recs = struct.get("recommendations", [])
            if isinstance(struct_recs, list):
                recs.extend(
                    [str(item).strip() for item in struct_recs if str(item).strip()]
                )

            recs.extend(
                self._parse_recommendations_from_text(
                    corr.get("correlation_analysis", "")
                )
            )

            parsed = self._try_parse_json(corr.get("correlation_analysis", ""))
            if isinstance(parsed, dict):
                parsed_recs = parsed.get("recommendations", [])
                if isinstance(parsed_recs, list):
                    recs.extend(
                        [str(item).strip() for item in parsed_recs if str(item).strip()]
                    )

        # Preserve order and deduplicate
        unique_recs = list(dict.fromkeys([r for r in recs if r]))
        return (
            unique_recs[:10]
            if unique_recs
            else ["Review generated report for detailed actions."]
        )

    def _parse_recommendations_from_text(self, text: str) -> List[str]:
        if not text:
            return []

        lines = [line.strip(" -*\t") for line in text.splitlines()]
        extracted = []
        in_recommendation_section = False

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            lower = line.lower()
            if "recommendation" in lower:
                in_recommendation_section = True
                continue

            if in_recommendation_section:
                # Stop when another numbered major section starts
                if re.match(r"^\d+\.", line):
                    in_recommendation_section = False
                    continue
                extracted.append(line)

        return extracted[:5]

    def _extract_cves(
        self, analysis_summary: str, attack_details: List[Dict[str, Any]]
    ) -> List[str]:
        text_parts = [analysis_summary] + [
            a.get("analysis", "") for a in attack_details
        ]
        combined = "\n".join([t for t in text_parts if t])
        cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", combined, flags=re.IGNORECASE)
        normalized = [cve.upper() for cve in cves]
        return list(dict.fromkeys(normalized))

    def _derive_potential_impact(
        self, attack_details: List[Dict[str, Any]], analysis_summary: str
    ) -> str:
        for attack in attack_details:
            analysis = attack.get("analysis", "")
            if not analysis:
                continue

            lines = analysis.splitlines()
            capture = False
            impact_lines = []
            for line in lines:
                if "potential impact" in line.lower():
                    capture = True
                    continue
                if capture:
                    if re.match(r"^\d+\.", line.strip()):
                        break
                    cleaned = line.strip(" -*\t")
                    if cleaned:
                        impact_lines.append(cleaned)

            if impact_lines:
                return " ".join(impact_lines[:3])

        return analysis_summary[:300]

    def _try_parse_json(self, text: str) -> Any:
        if not text:
            return None

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(0))
        except Exception:
            return None

    def ask_question(
        self, logs: str, report: str, question: str, role: str = "SOC Analyst"
    ) -> str:
        """
        Answer questions about the analysis

        Args:
            logs: Original logs
            report: Generated report
            question: User question
            role: Analyst role

        Returns:
            Answer to the question
        """
        return self.chat_agent.execute(role, logs, report, question)

    def export_results(self, results: Dict[str, Any], output_dir: str = "./output"):
        """
        Export analysis results to files

        Args:
            results: Analysis results
            output_dir: Output directory
        """
        import os
        from datetime import datetime

        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export text report
        report_file = os.path.join(output_dir, f"security_report_{timestamp}.txt")
        with open(report_file, "w") as f:
            f.write(results["report"])

        print(f"✓ Report exported to: {report_file}")

        # Export JSON data
        json_file = os.path.join(output_dir, f"analysis_data_{timestamp}.json")
        self.report_agent.export_json(
            {
                "metrics": results["metrics"],
                "analysis_summary": results["analysis_summary"],
                "attack_count": len(results["attack_details"]),
                "correlation_count": len(results["correlation_results"]),
            },
            json_file,
        )

        print(f"✓ Data exported to: {json_file}")

        return {"report_file": report_file, "json_file": json_file}


