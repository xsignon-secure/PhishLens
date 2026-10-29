"""Platform admin: whoever runs this PhishLens server.

Signs in with ADMIN_PASSWORD at /platform. Creates companies and their
owners, suspends companies, and resends an owner's login details. It sees
company names and their people, never their domains, scans or reports.
"""
import hmac
import secrets
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import audit, credentials, mailer, models, security
from ..config import settings
from ..database import get_db
from ..deps import auth_limit
from .users import _create, _queue_credentials, user_out

router = APIRouter(prefix="/api/platform", tags=["platform"])
COOKIE = "platform_token"


class PlatformLoginIn(BaseModel):
    password: str = Field(min_length=1, max_length=500)

    model_config = {"extra": "forbid"}


class CompanyIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    owner_email: str = Field(min_length=3, max_length=320)
    owner_name: str = Field(default="", max_length=200)
    send_email: bool = True

    model_config = {"extra": "forbid"}


class OwnerIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    full_name: str = Field(default="", max_length=200)
    send_email: bool = True

    model_config = {"extra": "forbid"}


class _Platform:
    """Stands in for the acting user when an owner is created: owners can only
    be made here."""
    role = "platform"
    id = None

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id


def require_platform(request: Request) -> bool:
    claims = security.decode_token(request.cookies.get(COOKIE) or "", allowed_types=("platform",))
    if not settings.ADMIN_PASSWORD or not claims \
            or not hmac.compare_digest(claims.get("pw", ""), security.platform_fingerprint()):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return True


@router.post("/login")
def platform_login(payload: PlatformLoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    if not settings.ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="The platform page is off: set ADMIN_PASSWORD on the server")
    auth_limit(request, "platform-login", "platform", limit=5)
    ip = request.client.host if request.client else None
    if not hmac.compare_digest(payload.password.encode(), settings.ADMIN_PASSWORD.encode()):
        audit.log(db, "platform.login_failed", ip=ip, detail={"severity": "high"})
        raise HTTPException(status_code=401, detail="Wrong password")
    audit.log(db, "platform.login", ip=ip)
    response.set_cookie(COOKIE, security.create_platform_token(), httponly=True, secure=settings.cookie_secure,
                        samesite="strict", max_age=2 * 3600)
    response.set_cookie("csrf_token", secrets.token_urlsafe(32), secure=settings.cookie_secure,
                        samesite="strict", max_age=2 * 3600)
    return {"ok": True}


@router.post("/logout")
def platform_logout(response: Response):
    response.delete_cookie(COOKIE, httponly=True, secure=settings.cookie_secure, samesite="strict")
    return {"ok": True}


def _company_out(db: Session, t: models.Tenant) -> dict:
    people = (db.query(models.User.role, func.count()).filter(models.User.tenant_id == t.id)
              .filter(~models.User.email.like("%.invalid")).group_by(models.User.role).all())
    owners = (db.query(models.User).filter(models.User.tenant_id == t.id, models.User.role == "owner")
              .order_by(models.User.created_at).all())
    return {"id": t.id, "name": t.name, "status": t.status, "created_at": t.created_at.isoformat() + "Z",
            "users": {role: n for role, n in people}, "own_mail_server": bool((t.smtp or {}).get("host")),
            "owners": [user_out(o) for o in owners if mailer.real_email(o.email)]}


@router.get("/companies")
def list_companies(db: Session = Depends(get_db), _: bool = Depends(require_platform)):
    return [_company_out(db, t) for t in db.query(models.Tenant).order_by(models.Tenant.created_at).all()]


@router.post("/companies", status_code=201)
def create_company(payload: CompanyIn, request: Request, background: BackgroundTasks,
                   db: Session = Depends(get_db), _: bool = Depends(require_platform)):
    tenant = models.Tenant(name=payload.name.strip())
    db.add(tenant)
    db.flush()
    try:
        owner, temp = _create(db, _Platform(tenant.id), payload.owner_email, payload.owner_name, "owner")
    except HTTPException:
        db.rollback()
        raise
    _queue_credentials(request, background, owner, temp, payload.send_email, db)
    audit.log(db, "platform.company_create", tenant_id=tenant.id,
              ip=request.client.host if request.client else None, detail={"owner": owner.email})
    return {**_company_out(db, tenant), "temporary_password": temp}


@router.post("/companies/{tenant_id}/owners", status_code=201)
def add_owner(tenant_id: str, payload: OwnerIn, request: Request, background: BackgroundTasks,
              db: Session = Depends(get_db), _: bool = Depends(require_platform)):
    """Another owner, or the first real owner of a company from before
    accounts existed."""
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Company not found")
    owner, temp = _create(db, _Platform(tenant.id), payload.email, payload.full_name, "owner")
    _queue_credentials(request, background, owner, temp, payload.send_email, db)
    audit.log(db, "platform.owner_create", tenant_id=tenant.id,
              ip=request.client.host if request.client else None, detail={"owner": owner.email})
    return {**user_out(owner), "temporary_password": temp}


@router.post("/owners/{user_id}/resend")
def resend_owner(user_id: str, request: Request, background: BackgroundTasks,
                 db: Session = Depends(get_db), _: bool = Depends(require_platform)):
    owner = db.query(models.User).filter(models.User.id == user_id, models.User.role == "owner").first()
    if not owner or not mailer.real_email(owner.email):
        raise HTTPException(status_code=404, detail="Owner not found")
    owner.status = "pending"
    temp = credentials.set_temporary_password(db, owner)
    # A lost authenticator is the usual reason an owner needs new details.
    security.set_totp_secret(owner, None)
    owner.mfa_enabled, owner.recovery_codes = False, None
    db.commit()
    _queue_credentials(request, background, owner, temp, True, db)
    audit.log(db, "platform.owner_resend", tenant_id=owner.tenant_id,
              ip=request.client.host if request.client else None, detail={"owner": owner.email})
    return {**user_out(owner), "temporary_password": temp}


def _set_status(db: Session, request: Request, tenant_id: str, status: str) -> dict:
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Company not found")
    tenant.status = status
    if status == "suspended":
        now = datetime.utcnow()
        for row in db.query(models.UserSession).filter(models.UserSession.tenant_id == tenant.id,
                                                       models.UserSession.revoked_at.is_(None)):
            row.revoked_at, row.revoked_reason = now, "company_suspended"
    db.commit()
    audit.log(db, f"platform.company_{'suspend' if status == 'suspended' else 'reactivate'}",
              tenant_id=tenant.id, ip=request.client.host if request.client else None,
              detail={"severity": "high"})
    return _company_out(db, tenant)


@router.post("/companies/{tenant_id}/suspend")
def suspend_company(tenant_id: str, request: Request, db: Session = Depends(get_db),
                    _: bool = Depends(require_platform)):
    return _set_status(db, request, tenant_id, "suspended")


@router.post("/companies/{tenant_id}/reactivate")
def reactivate_company(tenant_id: str, request: Request, db: Session = Depends(get_db),
                       _: bool = Depends(require_platform)):
    return _set_status(db, request, tenant_id, "active")
