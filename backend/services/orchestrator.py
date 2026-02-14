from typing import Dict, Any
from agents import (
    LogAnalysisAgent,
    AttackDetectionAgent,
    CorrelationAgent,
    ChatAgent,
    ReportGenerationAgent
)


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
        
        print("[Orchestrator] All agents initialized")
    
    def analyze_logs(self, logs: str, role: str = "SOC Analyst", pattern: str = "general") -> Dict[str, Any]:
        """
        Perform comprehensive log analysis using all agents
        
        Args:
            logs: Raw log data
            role: Analyst role/context
            pattern: Specific pattern to focus on
            
        Returns:
            Complete analysis results
        """
        print("\n" + "="*80)
        print("STARTING COMPREHENSIVE SECURITY ANALYSIS")
        print("="*80 + "\n")
        
        results = {}
        
        # Step 1: Extract metrics and basic analysis
        print("📊 Step 1: Extracting metrics and performing initial analysis...")
        metrics = self.log_analysis_agent.extract_metrics(logs)
        analysis_summary = self.log_analysis_agent.execute(role, logs, pattern)
        
        results['metrics'] = metrics
        results['analysis_summary'] = analysis_summary
        
        print(f"   ✓ Found {metrics['event_count']} total events")
        print(f"   ✓ Identified {len(metrics['error_lines'])} error/suspicious events")
        print(f"   ✓ Detected {len(metrics['attack_lines'])} potential attack indicators")
        
        # Step 2: Detailed attack analysis
        print("\n🔍 Step 2: Performing detailed attack analysis...")
        attack_details = []
        
        # Analyze error lines and attack lines
        suspicious_logs = list(set(metrics['error_lines'] + metrics['attack_lines']))
        
        if suspicious_logs:
            attack_details = self.attack_detection_agent.batch_analyze(
                suspicious_logs[:20],  # Limit to top 20 to avoid overload
                context=f"Total events: {metrics['event_count']}"
            )
            print(f"   ✓ Analyzed {len(attack_details)} suspicious log entries")
        else:
            print("   ℹ No suspicious log entries detected")
        
        results['attack_details'] = attack_details
        
        # Step 3: Correlation and false positive detection
        print("\n🔗 Step 3: Correlating events and detecting false positives...")
        correlation_results = []
        
        if suspicious_logs:
            # Group related events
            event_groups = self.correlation_agent.group_related_events(suspicious_logs)
            
            print(f"   ✓ Identified {len(event_groups)} correlation groups")
            
            # Analyze each group
            for group in event_groups[:10]:  # Limit to top 10 groups
                corr_result = self.correlation_agent.execute(
                    group,
                    metadata={"system_info": "Production environment"}
                )
                correlation_results.append(corr_result)
            
            # Count false positives
            fp_count = sum(1 for cr in correlation_results 
                          if cr.get('auto_fp_detection', {}).get('likely_false_positive'))
            print(f"   ✓ Detected {fp_count} likely false positives")
        
        results['correlation_results'] = correlation_results
        
        # Step 4: Generate comprehensive report
        print("\n📄 Step 4: Generating comprehensive security report...")
        report = self.report_agent.execute(
            analysis_summary=analysis_summary,
            attack_details=attack_details,
            correlation_results=correlation_results,
            metrics=metrics
        )
        
        results['report'] = report
        print("   ✓ Report generated successfully")
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80 + "\n")
        
        return results
    
    def ask_question(self, logs: str, report: str, question: str, role: str = "SOC Analyst") -> str:
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
        with open(report_file, 'w') as f:
            f.write(results['report'])
        
        print(f"✓ Report exported to: {report_file}")
        
        # Export JSON data
        json_file = os.path.join(output_dir, f"analysis_data_{timestamp}.json")
        self.report_agent.export_json(
            {
                'metrics': results['metrics'],
                'analysis_summary': results['analysis_summary'],
                'attack_count': len(results['attack_details']),
                'correlation_count': len(results['correlation_results'])
            },
            json_file
        )
        
        print(f"✓ Data exported to: {json_file}")
        
        return {
            'report_file': report_file,
            'json_file': json_file
        }