import json
import logging
from typing import Dict, List
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

class ResultAggregator:
    def __init__(self):
        self.results = {
            "semgrep": [],
            "snyk": [],
            "zap": []
        }
        
    def add_results(self, scanner: str, findings: List[Dict]):
        """Add scanner results"""
        if scanner in self.results:
            self.results[scanner] = findings
    
    def aggregate(self) -> Dict:
        """Aggregate all scanner results"""
        all_findings = []
        
        for scanner, findings in self.results.items():
            all_findings.extend(findings)
        
        for finding in all_findings:
            finding["finding_id"] = self._generate_finding_id(finding)
        
        severity_counts = self._count_by_severity(all_findings)
        
        aggregated = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "findings": all_findings,
            "critical_findings": [f for f in all_findings if f["severity"] in ["CRITICAL", "HIGH"]]
        }
        
        logger.info(f"Aggregated {len(all_findings)} total findings")
        return aggregated
    
    def _generate_finding_id(self, finding: Dict) -> str:
        """Generate unique ID for a finding"""
        key_attrs = f"{finding.get('scan_type', '')}-{finding.get('title', '')}-{finding.get('file_path', '')}"
        return hashlib.sha256(key_attrs.encode()).hexdigest()[:16]
    
    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            severity = finding.get("severity", "INFO")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def export_json(self, filepath: str):
        """Export aggregated results to JSON file"""
        results = self.aggregate()
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results exported to {filepath}")