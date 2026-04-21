# app/notifications.py
# Email notifications for high-severity security alerts.
#
# Configure via environment variables:
#   SMTP_HOST        — e.g. smtp.gmail.com
#   SMTP_PORT        — default 587 (TLS)
#   SMTP_USER        — sender email address
#   SMTP_PASS        — sender password / app password
#   ALERT_EMAIL_TO   — comma-separated recipient list

import os
import logging
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("notifications")

SMTP_HOST   = os.getenv("SMTP_HOST",       "")
SMTP_PORT   = int(os.getenv("SMTP_PORT",   "587"))
SMTP_USER   = os.getenv("SMTP_USER",       "")
SMTP_PASS   = os.getenv("SMTP_PASS",       "")
EMAIL_TO    = os.getenv("ALERT_EMAIL_TO",  "")


def is_configured() -> bool:
    return all([SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_TO])


def _send(subject: str, html: str) -> None:
    """Blocking SMTP send — always called in a background thread."""
    recipients = [r.strip() for r in EMAIL_TO.split(",") if r.strip()]
    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ", ".join(recipients)
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, recipients, msg.as_string())

        logger.info(f"Alert email sent to {recipients}")
    except Exception as e:
        logger.error(f"Email send failed: {e}")


def notify_alert(alert: dict) -> None:
    """
    Send an email for a HIGH or CRITICAL alert.
    No-op if SMTP is not configured.
    Fires in a daemon thread so it never blocks detection.
    """
    if alert.get("severity") not in ("HIGH", "CRITICAL"):
        return
    if not is_configured():
        logger.debug("SMTP not configured — skipping alert email.")
        return

    severity = alert["severity"]
    colour   = "#ff6b8a" if severity == "CRITICAL" else "#fb923c"
    subject  = f"[ChuggOps HealthSec] {severity} — {alert['alert_type'].replace('_', ' ')}"

    html = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#07061a;font-family:Arial,sans-serif;">
<div style="max-width:580px;margin:32px auto;background:#0e0c24;border:1px solid #262360;
            border-top:3px solid {colour};border-radius:8px;overflow:hidden;">

  <div style="padding:24px 28px;border-bottom:1px solid #262360;">
    <div style="font-size:10px;color:#524b82;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:6px;">
      ChuggOps HealthSec AI · Security Alert
    </div>
    <div style="font-size:24px;font-weight:700;color:{colour};">
      {severity}: {alert['alert_type'].replace('_', ' ')}
    </div>
  </div>

  <div style="padding:24px 28px;">
    <div style="font-size:10px;color:#524b82;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:8px;">
      DETAILS
    </div>
    <div style="font-size:14px;color:#9987c7;line-height:1.7;
                background:#141230;border-left:2px solid {colour};
                padding:12px 16px;border-radius:4px;">
      {alert.get('description', 'No description available.')}
    </div>
  </div>

  <div style="padding:16px 28px;border-top:1px solid #262360;background:#07061a;">
    <div style="font-size:11px;color:#524b82;">
      Detected at {alert.get('created_at', 'Unknown')} UTC.
      Log in to ChuggOps HealthSec AI to investigate and raise an incident.
    </div>
  </div>

</div>
</body>
</html>
"""
    threading.Thread(target=_send, args=(subject, html), daemon=True).start()
