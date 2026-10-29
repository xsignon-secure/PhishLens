"""Signed-in sessions: one row per browser or device.

The browser holds two httpOnly cookies: a short access token (names the
session) and a refresh token. When the access token expires, the middleware
in app/main.py swaps the refresh token for a new pair (rotation). A refresh
token presented again after it was rotated means it was copied: the session
is ended and audited. The one exception is a few seconds of grace, because a
page fires several requests at once with the same cookie.
"""
import secrets
from datetime import datetime, timedelta

from fastapi import Request, Response
from sqlalchemy.orm import Session

from . import models, security
from .config import settings

REFRESH_COOKIE = "refresh_token"
REFRESH_PATH = "/"
ROTATION_GRACE = timedelta(seconds=30)


def _device(request: Request | None) -> str | None:
    return (request.headers.get("user-agent") or "")[:200] if request else None


def _ip(request: Request | None) -> str | None:
    return request.client.host if request and request.client else None


def create(db: Session, user: models.User, request: Request | None, *, mfa: bool = False) -> tuple[str, str, models.UserSession]:
    """A new session for a user who just proved who they are. Returns
    (access token, refresh token, session)."""
    refresh = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    row = models.UserSession(
        user_id=user.id, tenant_id=user.tenant_id, refresh_hash=security.token_hash(refresh),
        device=_device(request), ip=_ip(request), mfa_at=now if mfa else None,
        created_at=now, last_used_at=now, expires_at=now + timedelta(hours=settings.SESSION_MAX_HOURS))
    db.add(row)
    user.last_login_at = now
    db.commit()
    return access_token(user, row), refresh, row


def access_token(user: models.User, row: models.UserSession) -> str:
    return security.create_access_token(user_id=user.id, tenant_id=row.tenant_id, session_id=row.id,
                                        role=user.role, version=user.token_version or 0)


def is_live(row: models.UserSession | None, now: datetime | None = None) -> bool:
    now = now or datetime.utcnow()
    return bool(row) and row.revoked_at is None and row.expires_at > now \
        and row.last_used_at > now - timedelta(minutes=settings.SESSION_IDLE_MINUTES)


def refresh(db: Session, raw: str, request: Request | None) -> tuple[str, str, models.UserSession] | None:
    """Swap a refresh token for a new access + refresh pair. None when the
    token is unknown, expired or replayed (which also ends the session)."""
    from . import audit
    digest = security.token_hash(raw)
    now = datetime.utcnow()
    row = db.query(models.UserSession).filter(models.UserSession.refresh_hash == digest).first()
    if row is None:
        old = db.query(models.UserSession).filter(models.UserSession.prev_refresh_hash == digest).first()
        if old is None:
            return None
        user = db.get(models.User, old.user_id)
        if old.rotated_at and now - old.rotated_at < ROTATION_GRACE and is_live(old, now) and user:
            # Parallel requests from one page: hand out an access token for
            # the same session, without rotating again.
            return access_token(user, old), None, old
        if old.revoked_at is None:
            revoke(db, old, "refresh_replay")
            audit.log(db, "security.refresh_token_replay", user=user, tenant_id=old.tenant_id,
                      detail={"severity": "critical", "session": old.id}, ip=_ip(request))
        return None
    if not is_live(row, now):
        return None
    user = db.get(models.User, row.user_id)
    if not user or not account_usable(user):
        revoke(db, row, "account_disabled")
        return None
    new_raw = secrets.token_urlsafe(32)
    row.prev_refresh_hash, row.refresh_hash = row.refresh_hash, security.token_hash(new_raw)
    row.rotated_at = row.last_used_at = now
    row.ip = _ip(request) or row.ip
    db.commit()
    return access_token(user, row), new_raw, row


def account_usable(user: models.User) -> bool:
    tenant = user.tenant
    return user.is_active and user.status == "active" and tenant is not None and tenant.status == "active"


def account_usable_or_pending(user: models.User) -> bool:
    """For the sign-in steps: a new account may still be on its temporary password."""
    tenant = user.tenant
    return user.is_active and user.status in ("active", "pending") and tenant is not None \
        and tenant.status == "active"


def revoke(db: Session, row: models.UserSession, reason: str) -> None:
    if row.revoked_at is None:
        row.revoked_at = datetime.utcnow()
        row.revoked_reason = reason
    db.commit()


def revoke_user(db: Session, user: models.User, reason: str, *, keep: str | None = None) -> int:
    """End every session of a user (role change, suspension, new password...),
    except `keep` (the session making the change)."""
    q = db.query(models.UserSession).filter(models.UserSession.user_id == user.id,
                                            models.UserSession.revoked_at.is_(None))
    if keep:
        q = q.filter(models.UserSession.id != keep)
    n = 0
    now = datetime.utcnow()
    for row in q.all():
        row.revoked_at, row.revoked_reason = now, reason
        n += 1
    db.commit()
    return n


def set_cookies(response: Response, access: str, refresh_raw: str | None, *, new_csrf: bool = False) -> None:
    """new_csrf only at sign-in: a page keeps its CSRF token across refreshes."""
    secure = settings.cookie_secure
    max_age = settings.SESSION_MAX_HOURS * 3600
    response.set_cookie("access_token", access, httponly=True, secure=secure, samesite="lax", max_age=max_age)
    if refresh_raw:
        response.set_cookie(REFRESH_COOKIE, refresh_raw, httponly=True, secure=secure, samesite="lax",
                            max_age=max_age, path=REFRESH_PATH)
    if new_csrf:
        response.set_cookie("csrf_token", secrets.token_urlsafe(32), secure=secure, samesite="lax", max_age=max_age)


def clear_cookies(response: Response) -> None:
    secure = settings.cookie_secure
    response.delete_cookie("access_token", httponly=True, secure=secure, samesite="lax")
    response.delete_cookie(REFRESH_COOKIE, httponly=True, secure=secure, samesite="lax", path=REFRESH_PATH)
    response.delete_cookie("csrf_token", secure=secure, samesite="lax")
