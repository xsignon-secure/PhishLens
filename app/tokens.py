"""Single-use auth tokens: email verification, password reset, team invites.

Only sha256 hashes are stored; the raw token is shown/emailed exactly once.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import models


def new_raw_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def create(db: Session, purpose: str, ttl_hours: int = 24,
           user_id: str | None = None, tenant_id: str | None = None,
           extra: dict | None = None) -> str:
    raw, digest = new_raw_token()
    db.add(models.AuthToken(
        user_id=user_id, tenant_id=tenant_id, purpose=purpose,
        token_hash=digest, expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
        extra=extra or {},
    ))
    db.commit()
    return raw


def peek(db: Session, raw: str, purpose: str) -> models.AuthToken | None:
    """Return the token row if valid and unused, WITHOUT consuming it."""
    digest = hashlib.sha256(raw.encode()).hexdigest()
    tok = (
        db.query(models.AuthToken)
        .filter(models.AuthToken.token_hash == digest,
                models.AuthToken.purpose == purpose,
                models.AuthToken.used_at.is_(None))
        .first()
    )
    if not tok or tok.expires_at < datetime.utcnow():
        return None
    return tok


def consume(db: Session, raw: str, purpose: str) -> models.AuthToken | None:
    """Validate and single-use a token. Returns the token row or None."""
    tok = peek(db, raw, purpose)
    if not tok:
        return None
    tok.used_at = datetime.utcnow()
    db.commit()
    return tok
