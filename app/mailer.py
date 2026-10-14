"""Outbound email alerts. stdlib smtplib only — no dependencies, no AI.

Deliberately boring: plain-text emails, sent only when SMTP_* is configured.
If email is unconfigured or fails, scanning and alerts keep working — the
alert rows in the database are the source of truth, email is a courtesy copy.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from . import models
from .config import settings

log = logging.getLogger("phishlens.mailer")


def is_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


def send_email(to: list[str], subject: str, body: str) -> bool:
    """Send a plain-text email. Returns True if handed to the SMTP server."""
    if not to or not is_configured():
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[{settings.APP_NAME}] {subject}"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    server = None
    try:
        # SMTP_USE_TLS=true: STARTTLS (port 587); false: implicit TLS (port 465).
        context = ssl.create_default_context()
        if settings.SMTP_USE_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20)
            server.starttls(context=context)
        else:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20,
                                      context=context)
        if settings.SMTP_USER:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)
        return True
    except Exception as exc:  # email must never break a scan
        log.warning("email send failed: %s", exc)
        return False
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def notify_monitor_alerts(db, monitor: "models.Monitor", scan: "models.Scan",
                          alerts: list["models.Alert"], prev_score: int | None) -> bool:
    """Email the tenant's owners about new monitor alerts. Returns True if sent."""
    owners = (
        db.query(models.User.email)
        .filter(models.User.tenant_id == monitor.tenant_id,
                models.User.role == "owner",
                models.User.is_active.is_(True))
        .all()
    )
    recipients = [email for (email,) in owners]
    if not recipients:
        return False
    lines = [
        f"{settings.APP_NAME} monitor alert",
        "",
        f"Domain:  {monitor.domain}",
        f"Score:   {prev_score} -> {scan.score} ({scan.grade})",
        f"Checked: {scan.created_at.isoformat() + 'Z' if scan.created_at else 'just now'}",
        "",
        "Alerts:",
    ]
    for alert in alerts:
        lines.append(f"- {alert.kind}: {alert.message}")
    lines += [
        "",
        f"Details: {settings.APP_URL}/dashboard",
        "",
        "Remove the monitor in your dashboard to stop these alerts.",
    ]
    return send_email(recipients, f"{monitor.domain} score alert", "\n".join(lines))
