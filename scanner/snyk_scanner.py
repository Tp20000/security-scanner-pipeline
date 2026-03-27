import subprocess
import json
import logging
from typing import Dict, List
from config import settings

logger = logging.getLogger(__name__)

class SnykScanner:
    def __init__(self, target_path: str = "."):
        self.target_path = target_path
        self.token = settings.SNYK_TOKEN
        
    def scan(self) -> Dict:
        """Run Snyk dependency scan"""
        logger.info(f"Running Snyk scan on {self.target_path}")
        
        if not self.token:
            logger.warning("SNYK_TOKEN not set, skipping Snyk scan")
            return {"scanner": "snyk", "status": "skipped", "findings": []}
        
        try:
            subprocess.run(
                ["snyk", "auth", self.token],
                capture_output=True,
                check=True
            )
            
            result = subprocess.run(
                ["snyk", "test", "--json"],
                cwd=self.target_path,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            output = json.loads(result.stdout) if result.stdout else {}
            parsed_findings = self._parse_results(output)
            
            logger.info(f"Snyk found {len(parsed_findings)} vulnerabilities")
            return {
                "scanner": "snyk",
                "status": "success",
                "findings": parsed_findings
            }
            
        except Exception as e:
            logger.error(f"Snyk scan failed: {str(e)}")
            return {"error": str(e), "findings": []}
    
    def _parse_results(self, results: Dict) -> List[Dict]:
        """Parse Snyk results into standardized format"""
        findings = []
        
        vulnerabilities = results.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low").upper()
            
            finding = {
                "scan_type": "SCA",
                "severity": severity,
                "title": vuln.get("title", "Unknown Vulnerability"),
                "description": vuln.get("description", ""),
                "package_name": vuln.get("packageName", ""),
                "cve_id": vuln.get("identifiers", {}).get("CVE", [None])[0] if vuln.get("identifiers", {}).get("CVE") else vuln.get("id"),
                "remediation": f"Upgrade to {vuln.get('upgradePath', ['No fix available'])[-1]}",
                "raw_data": vuln
            }
            findings.append(finding)
        
        return findings