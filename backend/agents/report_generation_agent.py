from typing import Dict, Any, List
from agents.base_agent import BaseAgent
from datetime import datetime
import json


class ReportGenerationAgent(BaseAgent):
    """
    Agent responsible for generating comprehensive security reports
    """

    def __init__(self, llm):
        super().__init__(llm, "ReportGenerationAgent")

    def execute(
        self,
        analysis_summary: str,
        attack_details: List[Dict[str, Any]],
        correlation_results: List[Dict[str, Any]],
        metrics: Dict[str, Any],
    ) -> str:
        """
        Generate comprehensive security report

        Args:
            analysis_summary: Overall analysis summary
            attack_details: Detailed attack analyses
            correlation_results: Correlation analysis results
            metrics: Log metrics

        Returns:
            Formatted report
        """
        self.log_activity("Generating comprehensive security report")

        report = []
        report.append("=" * 80)
        report.append("SECURITY OPERATIONS CENTER - THREAT ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        report.append("")

        # Executive Summary
        report.append("=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)
        report.append(analysis_summary)
        report.append("")

        # Metrics Overview
        report.append("=" * 80)
        report.append("METRICS OVERVIEW")
        report.append("=" * 80)
        report.append(f"Total Events Analyzed: {metrics.get('event_count', 0)}")
        report.append(f"Event Distribution: {metrics.get('event_distribution', {})}")
        report.append(f"Unique Source IPs: {len(metrics.get('top_ips', []))}")
        report.append(f"Error/Attack Events: {len(metrics.get('error_lines', []))}")
        report.append("")

        if metrics.get("top_ips"):
            report.append("Top Source IPs:")
            for ip, count in metrics["top_ips"][:5]:
                report.append(f"  - {ip}: {count} events")
        report.append("")

        # Detailed Attack Analysis
        if attack_details:
            report.append("=" * 80)
            report.append("DETAILED ATTACK ANALYSIS")
            report.append("=" * 80)
            report.append(f"Total Attacks Detected: {len(attack_details)}")
            report.append("")

            for idx, attack in enumerate(attack_details, 1):
                report.append("-" * 80)
                report.append(f"ATTACK #{idx}")
                report.append("-" * 80)
                report.append("Log Entry:")
                report.append(f"  {attack['log_entry']}")
                report.append("")
                report.append(
                    f"Detected Patterns: {', '.join(attack.get('detected_patterns', ['Unknown']))}"
                )
                report.append("")
                report.append("Analysis:")
                report.append(attack["analysis"])
                report.append("")

        # Correlation Analysis
        if correlation_results:
            report.append("=" * 80)
            report.append("CORRELATION ANALYSIS & FALSE POSITIVE DETECTION")
            report.append("=" * 80)

            for idx, corr in enumerate(correlation_results, 1):
                report.append("-" * 80)
                report.append(f"CORRELATION GROUP #{idx}")
                report.append("-" * 80)
                report.append(f"Related Events: {len(corr.get('events', []))}")
                report.append("")

                fp_check = corr.get("auto_fp_detection", {})
                if fp_check.get("likely_false_positive"):
                    report.append("⚠️ LIKELY FALSE POSITIVE")
                    report.append(
                        f"Detected Patterns: {fp_check.get('detected_patterns', [])}"
                    )
                    report.append("")

                report.append("AI Correlation Analysis:")
                report.append(corr.get("correlation_analysis", "N/A"))
                report.append("")

        # Recommendations
        report.append("=" * 80)
        report.append("IMMEDIATE ACTION ITEMS")
        report.append("=" * 80)
        report.append("Based on the analysis, the following actions are recommended:")
        report.append("")

        true_positives = [
            a for a in attack_details if "TRUE" in a.get("analysis", "").upper()
        ]

        if true_positives:
            report.append("🔴 CRITICAL ACTIONS:")
            report.append("  1. Block identified malicious IPs immediately")
            report.append("  2. Escalate to incident response team")
            report.append("  3. Review and update firewall rules")
            report.append("  4. Enable additional monitoring on affected systems")
        else:
            report.append("✅ No critical threats detected requiring immediate action")
            report.append("  - Continue monitoring")
            report.append("  - Review false positives for tuning detection rules")

        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)

    def export_json(self, report_data: Dict[str, Any], filepath: str):
        """
        Export report data as JSON

        Args:
            report_data: Report data to export
            filepath: Output file path
        """
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        self.log_activity(f"Report exported to {filepath}")
