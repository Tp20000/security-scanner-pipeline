import subprocess
import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class SemgrepScanner:
    def __init__(self, target_path: str = "."):
        self.target_path = target_path
        
    def scan(self) -> Dict:
        """Run Semgrep SAST scan"""
        logger.info(f"Running Semgrep scan on {self.target_path}")
        
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--config=auto",
                    "--json",
                    "--quiet",
                    self.target_path
                ],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode not in [0, 1]:
                logger.error(f"Semgrep failed: {result.stderr}")
                return {"error": result.stderr, "findings": []}
            
            findings = json.loads(result.stdout) if result.stdout else {"results": []}
            parsed_findings = self._parse_results(findings)
            
            logger.info(f"Semgrep found {len(parsed_findings)} issues")
            return {
                "scanner": "semgrep",
                "status": "success",
                "findings": parsed_findings
            }
            
        except Exception as e:
            logger.error(f"Semgrep scan failed: {str(e)}")
            return {"error": str(e), "findings": []}
    
    def _parse_results(self, results: Dict) -> List[Dict]:
        """Parse Semgrep results into standardized format"""
        findings = []
        
        for result in results.get("results", []):
            severity = result.get("extra", {}).get("severity", "INFO").upper()
            if severity == "ERROR":
                severity = "HIGH"
            elif severity == "WARNING":
                severity = "MEDIUM"
            
            finding = {
                "scan_type": "SAST",
                "severity": severity,
                "title": result.get("check_id", "Unknown Issue"),
                "description": result.get("extra", {}).get("message", ""),
                "file_path": result.get("path", ""),
                "line_number": result.get("start", {}).get("line"),
                "cwe_id": result.get("extra", {}).get("metadata", {}).get("cwe", [None])[0] if isinstance(result.get("extra", {}).get("metadata", {}).get("cwe"), list) else None,
                "remediation": result.get("extra", {}).get("metadata", {}).get("fix", ""),
                "raw_data": result
            }
            findings.append(finding)
        
        return findings