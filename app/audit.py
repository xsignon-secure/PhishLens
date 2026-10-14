"""Append-only security audit log. Write-only from the app's perspective."""
from datetime import datetime

from fastapi import Request
from sqlalchemy.orm import Session

from . import models


def log(db: Session, action: str, user: "models.User | None" = None,
        tenant_id: str | None = None, detail: dict | None = None,
        ip: str | None = None) -> None:
    db.add(models.AuditEvent(
        tenant_id=tenant_id or (user.tenant_id if user else None),
        user_id=user.id if user else None,
        action=action,
        detail=detail or {},
        ip=ip,
    ))
    db.commit()


def log_request(db: Session, request: Request, action: str,
                user: "models.User | None" = None, detail: dict | None = None) -> None:
    ip = request.client.host if request.client else None
    # never store raw secrets in the audit trail
    safe = {k: v for k, v in (detail or {}).items() if "password" not in k and "token" not in k}
    log(db, action, user=user, detail=safe, ip=ip)
