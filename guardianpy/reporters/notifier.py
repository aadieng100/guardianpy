import json
import urllib.request
from urllib.error import URLError, HTTPError
from guardianpy.config import Config

def send_security_alert(findings: list) -> bool:
    """
    Sends a summary alert to Slack or Discord webhooks if configured.
    """
    if not Config.is_notifier_enabled():
        # Silent return if no webhooks are configured
        return False

    total_issues = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    
    # Construct a clean text summary
    message_text = (
        f"🚨 *GuardianPy Security Alert* 🚨\n"
        f"Scan completed with blocking issues found.\n"
        f"• *Total Issues:* {total_issues}\n"
        f"• 🔥 *Critical:* {critical_count}\n"
        f"• ⚠️ *High:* {high_count}\n"
        f"Please check the generated Markdown artifact for full details."
    )

    # 1. Handle Slack Payload Format
    if Config.SLACK_WEBHOOK_URL:
        _dispatch_webhook(Config.SLACK_WEBHOOK_URL, {"text": message_text})

    # 2. Handle Discord Payload Format (Discord uses 'content' instead of 'text')
    if Config.DISCORD_WEBHOOK_URL:
        _dispatch_webhook(Config.DISCORD_WEBHOOK_URL, {"content": message_text})

    return True

def _dispatch_webhook(url: str, payload: dict):
    """
    Helper function to execute the native HTTP POST request securely.
    """
    try:
        data = json.dumps(payload).encode('utf-8')
        # We explicitly add a custom User-Agent to bypass Discord's Cloudflare anti-bot blocks
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'GuardianPy-SecurityBot/1.0'
        }
        
        req = urllib.request.Request(
            url, 
            data=data, 
            headers=headers
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status in [200, 204]:
                print(f"[+] Notification successfully sent to webhook endpoint.")
    except (HTTPError, URLError) as e:
        print(f"[-] Failed to dispatch security notification webhook: {e}")
    except Exception as e:
        print(f"[-] Unexpected error during notification dispatch: {e}")
