"""
SecureScript Platform — Alert Engine.

Sends async notifications when an XSS attack is blocked:
- Webhook: HTTP POST to a user-configured URL (Slack, Discord, webhook.site, etc.)
- Email: SMTP/SendGrid email to the project's configured alert address

Both functions:
- Are fully async (use httpx and aiosmtplib)
- Never raise exceptions to the caller (failures are logged, not propagated)
- Must always run as FastAPI BackgroundTask — never block the proxy response path
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("securescript.alerts")

# ---------------------------------------------------------------------------
# SMTP Configuration from environment
# ---------------------------------------------------------------------------
SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER: str = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM: str = os.environ.get("SMTP_FROM", "noreply@securescript.app")


# ---------------------------------------------------------------------------
# Webhook Alert
# ---------------------------------------------------------------------------
async def send_webhook_alert(webhook_url: str, payload: dict[str, Any]) -> bool:
    """
    POSTs an attack alert payload to the configured webhook URL.

    Retries once on failure. Swallows all exceptions — never raises.

    Args:
        webhook_url: The HTTP/HTTPS URL to POST the alert to.
        payload: The structured alert dictionary to send as JSON.

    Returns:
        True if the webhook was delivered successfully, False otherwise.
    """
    if not webhook_url:
        return False

    for attempt in range(2):  # try once, retry once
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json", "User-Agent": "SecureScript-WAF/1.0"},
                )
                if response.status_code < 500:
                    logger.info(
                        "[Alert:Webhook] Delivered to %s — HTTP %d (attempt %d)",
                        webhook_url,
                        response.status_code,
                        attempt + 1,
                    )
                    return True
                logger.warning(
                    "[Alert:Webhook] Server error %d for %s (attempt %d)",
                    response.status_code,
                    webhook_url,
                    attempt + 1,
                )
        except Exception as exc:
            logger.warning(
                "[Alert:Webhook] Delivery failed (attempt %d): %s", attempt + 1, exc
            )

    logger.error("[Alert:Webhook] All delivery attempts failed for %s", webhook_url)
    return False


# ---------------------------------------------------------------------------
# Email Alert
# ---------------------------------------------------------------------------
async def send_email_alert(to_email: str, incident: dict[str, Any]) -> bool:
    """
    Sends an HTML email alert about a blocked XSS attack via async SMTP.

    Requires SMTP_HOST, SMTP_USER, and SMTP_PASSWORD environment variables.
    Silently skips sending if SMTP is not configured. Swallows all exceptions.

    Args:
        to_email: Recipient email address.
        incident: The structured incident dictionary (from ``incident_to_dict``).

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    if not to_email:
        return False
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.debug("[Alert:Email] SMTP not configured — skipping email alert to %s", to_email)
        return False

    subject = (
        f"[SecureScript] XSS Attack Blocked — "
        f"{incident.get('attack_category', 'XSS')} "
        f"(Confidence: {incident.get('confidence_score', 0):.0%})"
    )
    html_body = _build_email_html(incident)

    try:
        import aiosmtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            msg,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            start_tls=True,
        )
        logger.info("[Alert:Email] Alert sent to %s for event %s", to_email, incident.get("event_id"))
        return True

    except ImportError:
        logger.warning("[Alert:Email] aiosmtplib not installed — email alerts disabled")
        return False
    except Exception as exc:
        logger.error("[Alert:Email] Failed to send alert to %s: %s", to_email, exc)
        return False


# ---------------------------------------------------------------------------
# Alert payload builder
# ---------------------------------------------------------------------------
def build_alert_payload(
    incident_dict: dict[str, Any],
    project_name: str,
    project_slug: str,
) -> dict[str, Any]:
    """
    Builds the standardised alert payload sent to webhooks and used in emails.

    Args:
        incident_dict: Output of ``incident_to_dict(incident)``.
        project_name: Human-readable project name.
        project_slug: Project slug for constructing the proxy path.

    Returns:
        Dictionary ready to be JSON-serialised and POSTed to a webhook.
    """
    return {
        "source": "SecureScript WAF",
        "event_id": incident_dict.get("event_id"),
        "project_name": project_name,
        "proxy_path": f"/proxy/{project_slug}/",
        "timestamp": incident_dict.get("timestamp"),
        "attack_type": incident_dict.get("attack_category", "XSS"),
        "confidence": incident_dict.get("confidence_score"),
        "url_path": incident_dict.get("url_path"),
        "client_ip": incident_dict.get("client_ip"),
        "http_method": incident_dict.get("http_method"),
        "detection_stage": incident_dict.get("detection_stage"),
        "severity": incident_dict.get("severity"),
        "trigger_tokens": incident_dict.get("trigger_tokens", []),
    }


# ---------------------------------------------------------------------------
# HTML email template
# ---------------------------------------------------------------------------
def _build_email_html(incident: dict[str, Any]) -> str:
    """Generates a clean HTML email body for an attack alert."""
    event_id = incident.get("event_id", "N/A")
    attack_type = incident.get("attack_category", "XSS")
    confidence = f"{incident.get('confidence_score', 0):.1%}"
    url_path = incident.get("url_path", "/")
    client_ip = incident.get("client_ip", "unknown")
    detection_stage = incident.get("detection_stage", "WAF")
    severity = incident.get("severity", "HIGH")
    timestamp = incident.get("timestamp", "")
    project_name = incident.get("project_name", "Your Project")
    proxy_path = incident.get("proxy_path", "")

    severity_color = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#65a30d",
    }.get(severity, "#ea580c")

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             background:#f9fafb; margin:0; padding:20px;">
  <div style="max-width:600px; margin:0 auto; background:#fff; border-radius:8px;
              border:1px solid #e5e7eb; overflow:hidden;">
    <div style="background:#1e293b; padding:24px 32px;">
      <h1 style="color:#fff; margin:0; font-size:20px;">
        🛡️ SecureScript — XSS Attack Blocked
      </h1>
      <p style="color:#94a3b8; margin:8px 0 0; font-size:14px;">
        Project: <strong style="color:#e2e8f0;">{project_name}</strong>
        &nbsp;·&nbsp; {proxy_path}
      </p>
    </div>
    <div style="padding:32px;">
      <table style="width:100%; border-collapse:collapse;">
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9; width:40%;
                     color:#64748b; font-size:14px;">Event ID</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     font-weight:600; font-family:monospace;">{event_id}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Severity</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;">
            <span style="background:{severity_color}; color:#fff; padding:2px 10px;
                         border-radius:12px; font-size:12px; font-weight:700;">
              {severity}
            </span>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Attack Type</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;">{attack_type}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Confidence</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     font-weight:600;">{confidence}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Path</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     font-family:monospace; font-size:13px;">{url_path}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Client IP</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     font-family:monospace;">{client_ip}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     color:#64748b; font-size:14px;">Detection Stage</td>
          <td style="padding:10px 0; border-bottom:1px solid #f1f5f9;
                     font-size:13px;">{detection_stage}</td>
        </tr>
        <tr>
          <td style="padding:10px 0; color:#64748b; font-size:14px;">Timestamp</td>
          <td style="padding:10px 0; font-size:13px;">{timestamp}</td>
        </tr>
      </table>
    </div>
    <div style="background:#f8fafc; padding:16px 32px; border-top:1px solid #e5e7eb;">
      <p style="margin:0; font-size:12px; color:#94a3b8; text-align:center;">
        SecureScript WAF Platform · This attack was automatically blocked.
      </p>
    </div>
  </div>
</body>
</html>
"""
