# Automated Security Scanner CI/CD Pipeline

Multi-scanner security pipeline integrating SAST, DAST, and SCA tools into GitHub Actions workflows.

## Features

- **SAST**: Semgrep for static code analysis
- **SCA**: Snyk for dependency vulnerability scanning  
- **DAST**: OWASP ZAP for dynamic application testing
- **Automated Reporting**: Unified JSON reports
- **Slack Notifications**: Real-time alerts for critical findings
- **GitHub Integration**: Auto-create issues for HIGH/CRITICAL CVEs

## Quick Start

This pipeline runs automatically on every pull request and push to main.

### View Results

1. Go to the **Actions** tab
2. Click on any workflow run
3. Download the **security-scan-results** artifact
4. View `aggregated-results.json`

