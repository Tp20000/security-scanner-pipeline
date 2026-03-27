import requests
import logging
from typing import Dict
from config import settings

logger = logging.getLogger(__name__)

class SlackNotifier:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or settings.SLACK_WEBHOOK_URL
        
    def send_scan_summary(self, aggregated_results: Dict):
        """Send scan summary to Slack"""
        if not self.webhook_url:
            logger.warning("SLACK_WEBHOOK_URL not set, skipping notification")
            return
        
        critical_findings = aggregated_results.get("critical_findings", [])
        severity_breakdown = aggregated_results.get("severity_breakdown", {})
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Security Scan Results"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Findings:*\n{aggregated_results.get('total_findings', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical/High:*\n{severity_breakdown.get('CRITICAL', 0) + severity_breakdown.get('HIGH', 0)}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*🔴 Critical:* {severity_breakdown.get('CRITICAL', 0)}"},
                    {"type": "mrkdwn", "text": f"*🟠 High:* {severity_breakdown.get('HIGH', 0)}"},
                    {"type": "mrkdwn", "text": f"*🟡 Medium:* {severity_breakdown.get('MEDIUM', 0)}"},
                    {"type": "mrkdwn", "text": f"*🟢 Low:* {severity_breakdown.get('LOW', 0)}"}
                ]
            }
        ]
        
        payload = {"blocks": blocks}
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            logger.info("Slack notification sent successfully")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {str(e)}")