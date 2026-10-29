"""User management, for a company's owners and admins.

No signup, no invitations: admins create accounts and PhishLens emails the
login details from the company's own mail server. Every lookup is by id AND
the admin's company, so another company's user is "not found" (404), never
"forbidden". Owners are created by the platform admin (/platform); inside a
company, owners manage admins and members, admins manage members.
"""
import csv
import io
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, credentials, mailer, models, passwords, plans, sessions
from ..config import settings
from ..database import get_db
from ..deps import rate_limit, require_admin, require_step_up
from .team import EMAIL_RE

router = APIRouter(prefix="/api/users", tags=["users"])
MAX_IMPORT_ROWS = 200


class UserIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    full_name: str = Field(default="", max_length=200)
    role: Literal["admin", "member"] = "member"
    # Optional: the admin's own temporary password; otherwise a random one.
    temporary_password: str = Field(default="", max_length=128)
    send_email: bool = True

    model_config = {"extra": "forbid"}


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    role: Literal["admin", "member"] | None = None

    model_config = {"extra": "forbid"}


class ImportIn(BaseModel):
    csv: str = Field(min_length=1, max_length=200_000)
    send_email: bool = True

    model_config = {"extra": "forbid"}


def user_out(u: models.User) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role,
            "status": "suspended" if not u.is_active else u.status, "mfa_enabled": bool(u.mfa_enabled),
            "last_login_at": iso(u.last_login_at), "created_at": iso(u.created_at),
            "temp_password_expires_at": iso(u.temp_password_expires_at) if u.must_change_password else None,
            "credentials_status": u.credentials_status, "credentials_error": u.credentials_error,
            "credentials_sent_at": iso(u.credentials_sent_at)}


def can_manage(actor: models.User, role: str) -> bool:
    """Owners manage admins and members; admins manage members. Nobody here
    manages owners (the platform admin does)."""
    return actor.role == "platform" or role == "member" or (role == "admin" and actor.role == "owner")


def _target(db: Session, actor: models.User, user_id: str) -> models.User:
    target = (db.query(models.User)
              .filter(models.User.id == user_id, models.User.tenant_id == actor.tenant_id).first())
    if not target or not mailer.real_email(target.email):
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Change your own account under Security")
    if not can_manage(actor, target.role):
        raise HTTPException(status_code=403, detail="Only an owner can change admins, and only the platform admin can change owners")
    return target


def _queue_credentials(request: Request, background: BackgroundTasks, user: models.User,
                       temp: str, send: bool, db: Session) -> None:
    # No mail server anywhere: say so now instead of showing "sending".
    if not send or not mailer.config_for(db.get(models.Tenant, user.tenant_id)):
        user.credentials_status, user.credentials_error = "manual", None
        db.commit()
        return
    # Each company's mail server is theirs, but its reputation is too: cap
    # how many login emails one company can send.
    rate_limit(request, f"credential-mail:{user.tenant_id}", settings.CREDENTIAL_EMAILS_PER_HOUR)
    user.credentials_status, user.credentials_error = "sending", None
    db.commit()
    background.add_task(credentials.deliver, user.id, user.tenant_id, temp)


def _create(db: Session, actor: models.User, email: str, full_name: str, role: str,
            temp_password: str = "") -> tuple[models.User, str]:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if not can_manage(actor, role):
        raise HTTPException(status_code=403, detail="Only an owner can create admins")
    if temp_password:
        try:
            passwords.check_policy(temp_password)
        except passwords.PasswordError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=409, detail="That email address is already in use")
    user = models.User(tenant_id=actor.tenant_id, email=email, full_name=full_name.strip() or None,
                       role=role, status="pending", password_hash="!")
    db.add(user)
    db.flush()
    return user, credentials.set_temporary_password(db, user, temp_password or None)


@router.get("")
def list_users(db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    rows = (db.query(models.User).filter(models.User.tenant_id == user.tenant_id)
            .order_by(models.User.created_at).all())
    return [user_out(u) for u in rows if mailer.real_email(u.email)]


def _seats(db: Session, tenant_id: str) -> int:
    """Accounts that count toward the plan: every real person, suspended ones too."""
    return sum(1 for (email,) in db.query(models.User.email).filter(models.User.tenant_id == tenant_id)
               if mailer.real_email(email))


@router.post("", status_code=201)
def create_user(payload: UserIn, request: Request, background: BackgroundTasks,
                db: Session = Depends(get_db), actor: models.User = Depends(require_step_up)):
    plans.check_limit(actor.tenant, "users", _seats(db, actor.tenant_id), "users")
    user, temp = _create(db, actor, payload.email, payload.full_name, payload.role, payload.temporary_password)
    _queue_credentials(request, background, user, temp, payload.send_email, db)
    audit.log_request(db, request, "user.create", actor,
                      {"target": user.email, "role": user.role, "emailed": payload.send_email})
    # Shown once, for admins who prefer to hand it over another way.
    return {**user_out(user), "temporary_password": temp}


@router.patch("/{user_id}")
def update_user(user_id: str, payload: UserPatch, request: Request, db: Session = Depends(get_db),
                actor: models.User = Depends(require_step_up)):
    target = _target(db, actor, user_id)
    if payload.full_name is not None:
        target.full_name = payload.full_name.strip() or None
    if payload.role and payload.role != target.role:
        if not can_manage(actor, payload.role):
            raise HTTPException(status_code=403, detail="Only an owner can make someone an admin")
        old, target.role = target.role, payload.role
        target.token_version = (target.token_version or 0) + 1
        db.commit()
        # New role, new sessions: nothing keeps running with the old rights.
        sessions.revoke_user(db, target, "role_change")
        audit.log_request(db, request, "user.role_change", actor,
                          {"target": target.email, "from": old, "to": target.role, "severity": "high"})
    db.commit()
    return user_out(target)


@router.post("/{user_id}/suspend")
def suspend_user(user_id: str, request: Request, db: Session = Depends(get_db),
                 actor: models.User = Depends(require_step_up)):
    target = _target(db, actor, user_id)
    target.status = "suspended"
    target.token_version = (target.token_version or 0) + 1
    db.commit()
    sessions.revoke_user(db, target, "suspended")
    audit.log_request(db, request, "user.suspend", actor, {"target": target.email, "severity": "high"})
    return user_out(target)


@router.post("/{user_id}/reactivate")
def reactivate_user(user_id: str, request: Request, background: BackgroundTasks,
                    db: Session = Depends(get_db), actor: models.User = Depends(require_step_up)):
    """Back on, with new login details (the old password is not restored)."""
    target = _target(db, actor, user_id)
    if target.status != "suspended":
        raise HTTPException(status_code=400, detail="This account isn't suspended")
    temp = credentials.set_temporary_password(db, target)
    _queue_credentials(request, background, target, temp, True, db)
    audit.log_request(db, request, "user.reactivate", actor, {"target": target.email})
    return {**user_out(target), "temporary_password": temp}


@router.post("/{user_id}/resend")
def resend_credentials(user_id: str, request: Request, background: BackgroundTasks,
                       db: Session = Depends(get_db), actor: models.User = Depends(require_step_up)):
    """New temporary password, emailed again. The previous one stops working.
    Also how a user who forgot their password gets back in."""
    target = _target(db, actor, user_id)
    if target.status == "suspended":
        raise HTTPException(status_code=400, detail="Reactivate the account first")
    temp = credentials.set_temporary_password(db, target)
    _queue_credentials(request, background, target, temp, True, db)
    audit.log_request(db, request, "user.credentials_resend", actor, {"target": target.email})
    return {**user_out(target), "temporary_password": temp}


@router.post("/{user_id}/reset-mfa")
def reset_mfa(user_id: str, request: Request, db: Session = Depends(get_db),
              actor: models.User = Depends(require_step_up)):
    """For a lost phone without recovery codes: the user sets up a new
    authenticator app at their next sign-in."""
    from ..security import set_totp_secret
    target = _target(db, actor, user_id)
    set_totp_secret(target, None)
    target.mfa_enabled, target.recovery_codes = False, None
    target.token_version = (target.token_version or 0) + 1
    db.commit()
    sessions.revoke_user(db, target, "mfa_reset")
    audit.log_request(db, request, "user.mfa_reset", actor, {"target": target.email, "severity": "high"})
    return user_out(target)


@router.delete("/{user_id}")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db),
                actor: models.User = Depends(require_step_up)):
    target = _target(db, actor, user_id)
    email = target.email
    sessions.revoke_user(db, target, "deleted")
    db.query(models.UserSession).filter(models.UserSession.user_id == target.id).delete()
    db.query(models.ApiKey).filter(models.ApiKey.user_id == target.id).delete()
    db.query(models.AuthToken).filter(models.AuthToken.user_id == target.id).delete()
    db.query(models.AuditEvent).filter(models.AuditEvent.user_id == target.id).update({"user_id": None})
    db.delete(target)
    db.commit()
    audit.log_request(db, request, "user.delete", actor, {"target": email, "severity": "critical"})
    return {"ok": True}


@router.post("/import")
def import_users(payload: ImportIn, request: Request, background: BackgroundTasks,
                 db: Session = Depends(get_db), actor: models.User = Depends(require_step_up)):
    """CSV with columns email, name, role (header optional). Each row is
    checked on its own: bad rows are reported and the good ones created."""
    rows = list(csv.reader(io.StringIO(payload.csv.strip())))
    if rows and rows[0] and rows[0][0].strip().lower() == "email":
        rows = rows[1:]
    if len(rows) > MAX_IMPORT_ROWS:
        raise HTTPException(status_code=400, detail=f"Import at most {MAX_IMPORT_ROWS} users at a time")
    results, created = [], 0
    for n, row in enumerate(rows, start=1):
        cells = [c.strip() for c in row] + ["", "", ""]
        email, name, role = cells[0], cells[1], (cells[2] or "member").lower()
        if not any(cells):
            continue
        try:
            if role not in ("admin", "member"):
                raise HTTPException(status_code=400, detail="Role must be admin or member")
            plans.check_limit(actor.tenant, "users", _seats(db, actor.tenant_id), "users")
            user, temp = _create(db, actor, email, name, role)
            _queue_credentials(request, background, user, temp, payload.send_email, db)
            results.append({"row": n, "email": user.email, "ok": True,
                             **({} if payload.send_email else {"temporary_password": temp})})
            created += 1
        except HTTPException as exc:
            db.rollback()
            results.append({"row": n, "email": email, "ok": False, "error": exc.detail})
    audit.log_request(db, request, "user.import", actor, {"created": created, "rows": len(results)})
    return {"created": created, "failed": len(results) - created, "rows": results}
