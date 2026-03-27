from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # GitHub
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_REPOSITORY: Optional[str] = None
    
    # Slack
    SLACK_WEBHOOK_URL: Optional[str] = None
    
    # Snyk
    SNYK_TOKEN: Optional[str] = None
    
    # Database
    DATABASE_URL: str = "postgresql://scanner:scanner123@localhost:5432/security_scans"
    
    # Scanning
    AUTO_CREATE_ISSUES: bool = True
    CRITICAL_SEVERITY_THRESHOLD: str = "HIGH"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()