"""Login details for accounts that admins create.

There is no signup and no invitation link. An admin creates the account;
PhishLens sets a random temporary password and emails it from the company's
own mail server (or the server-wide one). The temporary password works once,
for TEMP_PASSWORD_HOURS, and only to choose a real password. "Resend" always
makes a new one: the old one stops working and is never sent again.
"""
import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import audit, mailer, models, passwords
from .config import settings
from .database import SessionLocal

log = logging.getLogger("phishlens.credentials")


def set_temporary_password(db: Session, user: models.User, password: str | None = None) -> str:
    """Give the account a new one-time password (random unless the admin
    chose one), end its sessions, and return it for delivery."""
    from . import sessions
    temp = password or passwords.temporary_password()
    user.password_hash = passwords.hash_password(temp)
    user.must_change_password = True
    user.temp_password_expires_at = datetime.utcnow() + timedelta(hours=settings.TEMP_PASSWORD_HOURS)
    user.status = "pending"
    user.failed_logins, user.locked_until = 0, None
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    sessions.revoke_user(db, user, "credentials_reset")
    return temp


def _body(tenant: models.Tenant, user: models.User, temp: str) -> tuple[str, str]:
    """Plain text: names and the company's own wording are inserted as text,
    never interpreted, so they can't inject markup or template code."""
    company = tenant.brand_name or tenant.name
    subject = tenant.welcome_subject or f"Your {settings.APP_NAME} account for {company}"
    intro = tenant.welcome_message or (
        f"An account has been created for you on {settings.APP_NAME}, the email security "
        f"dashboard {company} uses.")
    hello = f"Hello {user.full_name}," if user.full_name else "Hello,"
    body = (f"{hello}\n\n{intro}\n\n"
            f"Sign in:            {settings.APP_URL}/login\n"
            f"Email:              {user.email}\n"
            f"Temporary password: {temp}\n\n"
            f"This password works once, for {settings.TEMP_PASSWORD_HOURS} hours. You'll choose your own\n"
            f"password when you sign in. If it expires, ask your administrator to send new details.\n\n"
            f"If you weren't expecting this email, ignore it and tell your IT team.\n")
    return subject, body


def deliver(user_id: str, tenant_id: str, temp: str) -> None:
    """Background job: send the login details. The job carries the company,
    and only that company's mail server is ever read for it."""
    db = SessionLocal()
    try:
        user = db.get(models.User, user_id)
        tenant = db.get(models.Tenant, tenant_id)
        if not user or not tenant or user.tenant_id != tenant.id:
            return  # account moved or deleted since the job was queued
        cfg = mailer.tenant_config(tenant) or mailer.server_config()
        if not cfg:
            user.credentials_status, user.credentials_error = "manual", "No mail server: give the password yourself"
            db.commit()
            return
        subject, body = _body(tenant, user, temp)
        try:
            mailer.deliver(cfg, mailer.build_message(cfg, [user.email], subject, body, prefix=False))
        except mailer.SmtpError as exc:
            user.credentials_status, user.credentials_error = "failed", str(exc)[:300]
            db.commit()
            audit.log(db, "user.credentials_failed", tenant_id=tenant.id,
                      detail={"target": user.email, "error": str(exc)[:200]})
            return
        user.credentials_status, user.credentials_error = "sent", None
        user.credentials_sent_at = datetime.utcnow()
        db.commit()
        audit.log(db, "user.credentials_sent", tenant_id=tenant.id,
                  detail={"target": user.email, "via": cfg["host"],
                          "own_server": cfg.get("pinned", False)})
    except Exception:  # a job must never crash the worker
        log.exception("credential delivery failed")
    finally:
        db.close()
