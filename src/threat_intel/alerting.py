import httpx
import logging
import os
from dotenv import load_dotenv
from threat_intel.models import ThreatEvent

load_dotenv()

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


def send_slack_alert(threat: ThreatEvent) -> bool:
    if not SLACK_WEBHOOK_URL:
        logger.error("SLACK_WEBHOOK_URL not found in .env file")
        return False

    message = build_slack_message(threat)

    try:
        response = httpx.post(
            SLACK_WEBHOOK_URL,
            json=message
        )

        if response. status_code == 200:
            logger.info(f"Slack alert sent for {threat.id}")
            return True
        else:
            logger.error(
                f"Slack alert failed: {response.status_code}"
                f"{response.text}"
            )
            return False

    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")
        return False


def build_slack_message(threat: ThreatEvent) -> dict:
    severity_emoji = get_severity_emoji(threat.severity)

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} CRITICAL THREAT DETECTED"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVE ID:*\n{threat.id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{threat.severity}/10"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Published:*\n{threat.published[:10]}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{threat.source}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{threat.description[:300]}"
                }
            },
            {
                "type": "divider"
            }
        ]
    }


def get_severity_emoji(severity: float) -> str:
    if severity >= 9.0:
        return "🔴"
    elif severity >= 7.0:
        return "🟠"
    elif severity >= 4.0:
        return "🟡"
    else:
        return "🟢"
