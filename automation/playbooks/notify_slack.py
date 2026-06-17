
import os
import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib import request, error
from datetime import datetime

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_EMAIL_TO    = os.getenv("ALERT_EMAIL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")

SEVERITY_COLOR = {
    "low":      "#36a64f",   # green
    "medium":   "#ff9900",   # orange
    "high":     "#e01e5a",   # red
    "critical": "#6e0000",   # dark red
}

SEVERITY_EMOJI = {
    "low":      "🟢",
    "medium":   "🟡",
    "high":     "🔴",
    "critical": "💀",
}


def _build_slack_payload(alert: dict, extra_message: str = "") -> dict:
    severity  = alert.get("severity", "medium")
    source_ip = alert.get("source_ip", "N/A")
    rule_name = alert.get("rule_name", "Unknown Rule")
    rule_id   = alert.get("rule_id", "")
    event     = alert.get("event", {})
    emoji     = SEVERITY_EMOJI.get(severity, "⚠️")
    color     = SEVERITY_COLOR.get(severity, "#ff9900")
    ts        = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    fields = [
        {"title": "Rule",      "value": f"`{rule_id}` {rule_name}", "short": False},
        {"title": "Source IP", "value": f"`{source_ip}`",           "short": True},
        {"title": "Severity",  "value": severity.upper(),           "short": True},
        {"title": "Time",      "value": ts,                         "short": True},
    ]

    if event.get("username"):
        fields.append({"title": "User", "value": event["username"], "short": True})
    if event.get("category"):
        fields.append({"title": "Category", "value": event["category"], "short": True})

    text = f"{emoji} *SIEM Alert: {rule_name}*"
    if extra_message:
        text += extra_message

    return {
        "text": text,
        "attachments": [{
            "color":  color,
            "fields": fields,
            "footer": "SIEM Lite",
            "ts":     int(datetime.utcnow().timestamp()),
        }],
    }


def _send_slack(payload: dict) -> tuple[bool, str]:
    if not SLACK_WEBHOOK_URL:
        return False, "SLACK_WEBHOOK_URL not configured"
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            if body == "ok":
                return True, "Slack notification sent"
            return False, f"Slack responded: {body}"
    except error.URLError as e:
        return False, f"Slack request failed: {e}"


def _build_email_body(alert: dict, extra_message: str = "") -> str:
    severity  = alert.get("severity", "medium").upper()
    rule_name = alert.get("rule_name", "Unknown Rule")
    rule_id   = alert.get("rule_id", "")
    source_ip = alert.get("source_ip", "N/A")
    event     = alert.get("event", {})
    ts        = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"SIEM Lite Alert",
        f"{'=' * 40}",
        f"Rule:      [{rule_id}] {rule_name}",
        f"Severity:  {severity}",
        f"Source IP: {source_ip}",
        f"Time:      {ts}",
        f"Category:  {event.get('category', 'N/A')}",
        f"Username:  {event.get('username', 'N/A')}",
        f"Message:   {event.get('message', 'N/A')}",
    ]
    if extra_message:
        lines.append(f"\nAction: {extra_message.strip()}")
    lines += [
        "",
        "Review and respond in the SIEM Lite dashboard.",
        f"{'=' * 40}",
        "This is an automated alert from SIEM Lite.",
    ]
    return "\n".join(lines)


def _send_email(alert: dict, extra_message: str = "") -> tuple[bool, str]:
    if not all([ALERT_EMAIL_TO, SMTP_USER, SMTP_PASS]):
        return False, "Email not configured (ALERT_EMAIL / SMTP_USER / SMTP_PASS missing)"
    try:
        severity  = alert.get("severity", "medium").upper()
        rule_name = alert.get("rule_name", "Unknown Rule")
        source_ip = alert.get("source_ip", "N/A")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SIEM-{severity}] {rule_name} — {source_ip}"
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO

        body = _build_email_body(alert, extra_message)
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [ALERT_EMAIL_TO], msg.as_string())

        return True, f"Email sent to {ALERT_EMAIL_TO}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, f"Email error: {e}"


def execute(alert_payload: dict, extra_message: str = "") -> dict:

    results = {}

    # Slack
    slack_ok, slack_msg = _send_slack(_build_slack_payload(alert_payload, extra_message))
    results["slack"] = {"status": "success" if slack_ok else "skipped", "message": slack_msg}
    logger.info(f"Slack: {slack_msg}")

    # Email
    email_ok, email_msg = _send_email(alert_payload, extra_message)
    results["email"] = {"status": "success" if email_ok else "skipped", "message": email_msg}
    logger.info(f"Email: {email_msg}")

    overall = "success" if (slack_ok or email_ok) else "skipped"
    return {"status": overall, "channels": results}
