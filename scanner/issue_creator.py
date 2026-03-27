import requests
import logging
from typing import Dict, List
from config import settings

logger = logging.getLogger(__name__)

class GitHubIssueCreator:
    def __init__(self, token: str = None, repository: str = None):
        self.token = token or settings.GITHUB_TOKEN
        self.repository = repository or settings.GITHUB_REPOSITORY
        self.api_base = "https://api.github.com"
        
    def create_issues_for_findings(self, findings: List[Dict]) -> List[int]:
        """Create GitHub issues for critical/high findings"""
        if not self.token or not self.repository:
            logger.warning("GitHub credentials not set, skipping issue creation")
            return []
        
        if not settings.AUTO_CREATE_ISSUES:
            logger.info("Auto-create issues disabled")
            return []
        
        created_issues = []
        critical_findings = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
        
        for finding in critical_findings[:5]:  # Limit to 5 issues to avoid spam
            issue_number = self._create_issue(finding)
            if issue_number:
                created_issues.append(issue_number)
        
        logger.info(f"Created {len(created_issues)} GitHub issues")
        return created_issues
    
    def _create_issue(self, finding: Dict) -> int:
        """Create a single GitHub issue"""
        title = f"🔒 [{finding.get('severity')}] {finding.get('title')}"
        
        body = f"""## Security Finding

**Severity:** {finding.get('severity')}
**Scan Type:** {finding.get('scan_type')}

### Description
{finding.get('description', 'No description available')}

"""
        
        if finding.get('file_path'):
            body += f"**File:** `{finding.get('file_path')}`"
            if finding.get('line_number'):
                body += f" (Line {finding.get('line_number')})"
            body += "\n\n"
        
        if finding.get('remediation'):
            body += f"### Remediation\n{finding.get('remediation')}\n\n"
        
        body += "---\n*This issue was automatically created by the Security Scanner Pipeline*"
        
        labels = [
            "security",
            f"severity:{finding.get('severity', 'unknown').lower()}"
        ]
        
        payload = {
            "title": title,
            "body": body,
            "labels": labels
        }
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.post(
                f"{self.api_base}/repos/{self.repository}/issues",
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            issue_number = response.json()["number"]
            logger.info(f"Created issue #{issue_number}: {title}")
            return issue_number
        except Exception as e:
            logger.error(f"Failed to create issue: {str(e)}")
            return None