"""
Security Webhook Dispatcher Engine
Sends automated real-time incident alerts to Slack, Discord, or Microsoft Teams webhooks
when CRITICAL or HIGH severity misconfigurations are detected or remediated.
"""

import os
import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

def dispatch_security_alert(finding, action="DETECTED", custom_webhook_url=None):
    """
    Dispatches a formatted security alert to the configured Webhook endpoint (Slack/Discord/Teams).
    Returns (success: bool, status_message: str)
    """
    webhook_url = custom_webhook_url or os.getenv("SECURITY_WEBHOOK_URL", "")
    
    res_name = finding.resource_rel.resource_name if getattr(finding, 'resource_rel', None) else finding.resource_id
    sev = getattr(finding, 'severity', 'HIGH')
    f_id = getattr(finding, 'finding_id', 'FINDING')
    title = getattr(finding, 'title', 'Security Misconfiguration')

    # Emoji & Color selection
    color_map = {
        'CRITICAL': 15671108, # Red
        'HIGH': 16348182,     # Orange
        'MEDIUM': 15380232,   # Yellow
        'LOW': 3717112        # Blue
    }
    color_code = color_map.get(sev, 15671108)

    # Discord-compatible Rich Embed
    payload = {
        "username": "CloudGuard SOC Security Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        "embeds": [
            {
                "title": f"🚨 [{sev}] Security Finding {action}: {title}",
                "description": f"**CloudGuard SOC Alert Notification**\n{getattr(finding, 'description', '')}",
                "color": color_code,
                "fields": [
                    {"name": "Resource", "value": f"`{res_name}`", "inline": True},
                    {"name": "Severity", "value": f"**{sev}**", "inline": True},
                    {"name": "Finding ID", "value": f"`{f_id}`", "inline": True},
                    {"name": "Recommendation", "value": getattr(finding, 'recommendation', 'Review in dashboard'), "inline": False}
                ],
                "footer": {"text": "CloudGuard SOC • Automated Cybersecurity Incident Response"}
            }
        ]
    }

    if not webhook_url:
        logger.info(f"[Webhook Simulation] Alert '{title}' on {res_name} logged. (Set SECURITY_WEBHOOK_URL to send live)")
        return True, "Alert logged (Webhook URL not set, simulated successfully)"

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'CloudGuard-SOC/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status in (200, 204):
                return True, "Webhook alert dispatched successfully."
            return False, f"Webhook responded with status {response.status}"
    except Exception as e:
        logger.warning(f"Webhook dispatch failed: {e}")
        return False, str(e)
