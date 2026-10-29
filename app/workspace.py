"""The single workspace. PhishLens has no user accounts: one admin password
(ADMIN_PASSWORD) opens the dashboard. Internally, all dashboard data still
belongs to one tenant row, acted on by one built-in admin user row, so every
query keeps its tenant filter."""
import hashlib
import hmac
import secrets

from sqlalchemy.orm import Session

from . import models
from .config import settings

ADMIN_PLACEHOLDER_EMAIL = "admin@phishlens.invalid"


def enabled() -> bool:
    return bool(settings.ADMIN_PASSWORD)


def check_password(password: str) -> bool:
    return enabled() and hmac.compare_digest((password or "").encode(), settings.ADMIN_PASSWORD.encode())


def password_fingerprint() -> str:
    """Goes into session tokens: changing ADMIN_PASSWORD signs everyone out."""
    return hmac.new(settings.SECRET_KEY.encode(), settings.ADMIN_PASSWORD.encode(), hashlib.sha256).hexdigest()[:16]


def admin_email() -> str | None:
    return settings.ADMIN_EMAIL.strip().lower() or None


def get_admin(db: Session) -> models.User:
    """The built-in admin user, created on first use. A database from before
    accounts were removed keeps its oldest team and that team's oldest owner."""
    user = (db.query(models.User).join(models.Tenant)
            .filter(models.User.role == "owner")
            .order_by(models.Tenant.created_at, models.User.created_at).first())
    if not user:
        tenant = (db.query(models.Tenant).order_by(models.Tenant.created_at).first()
                  or models.Tenant(name="PhishLens"))
        db.add(tenant)
        db.flush()
        user = models.User(tenant_id=tenant.id, email=ADMIN_PLACEHOLDER_EMAIL, role="owner",
                           is_verified=True, password_hash="!" + secrets.token_hex(16))
        db.add(user)
        db.commit()
        db.refresh(user)
    email = admin_email() or ADMIN_PLACEHOLDER_EMAIL
    if user.email != email and not db.query(models.User).filter(models.User.email == email).first():
        user.email = email  # alert emails and scheduled reports go here
        db.commit()
    return user


def real_email(email: str | None) -> bool:
    return bool(email) and not email.endswith(".invalid")
