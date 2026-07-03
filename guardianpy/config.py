import os

class Config:
    """
    Centralized configuration management for GuardianPy.
    Loads settings from environment variables with safe defaults.
    """
    # Target files for static scanning
    DEFAULT_DOCKERFILE_PATH = os.getenv("GUARDIAN_DOCKERFILE_PATH", "targets/Dockerfile.vuln")
    DEFAULT_TERRAFORM_PATH = os.getenv("GUARDIAN_TERRAFORM_PATH", "targets/main.tf.vuln")
    
    # Alerting configurations (Optional Webhooks)
    SLACK_WEBHOOK_URL = os.getenv("GUARDIAN_SLACK_WEBHOOK", "")
    DISCORD_WEBHOOK_URL = os.getenv("GUARDIAN_DISCORD_WEBHOOK", "")
    
    # Gatekeeper settings
    # If True, any CRITICAL or HIGH vulnerability will trigger an exit code 1
    FAIL_ON_SEVERITY = os.getenv("GUARDIAN_FAIL_ON_SEVERITY", "HIGH")
    
    @classmethod
    def is_notifier_enabled(cls) -> bool:
        """Checks if at least one alerting webhook is configured."""
        return bool(cls.SLACK_WEBHOOK_URL or cls.DISCORD_WEBHOOK_URL)
