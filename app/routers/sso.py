"""SSO (OpenID Connect): tenant configuration and the sign-in flow."""
import secrets
import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, models, security, sso
from ..config import settings
from ..database import get_db
from ..deps import auth_limit, get_current_user, require_owner
from .auth import _set_session_cookies

router = APIRouter(tags=["sso"])
COOKIE = "sso_state"


class SsoConfigIn(BaseModel):
    issuer: str = Field(min_length=8, max_length=300)
    client_id: str = Field(min_length=1, max_length=300)
    client_secret: str | None = Field(default=None, max_length=1000)
    email_domain: str = Field(min_length=3, max_length=253)
    enforced: bool = False


def _fail(message: str) -> RedirectResponse:
    resp = RedirectResponse("/login?sso_error=" + urllib.parse.quote(message), status_code=303)
    resp.delete_cookie(COOKIE, path="/api/auth/sso")
    return resp


@router.get("/api/team/sso")
def get_sso(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"configured": bool(t.sso_issuer), "issuer": t.sso_issuer, "client_id": t.sso_client_id,
            "email_domain": t.sso_email_domain, "enforced": bool(t.sso_enforced),
            "has_secret": bool(t.sso_client_secret), "redirect_uri": sso.redirect_uri()}


@router.put("/api/team/sso")
def set_sso(payload: SsoConfigIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(require_owner)):
    from ..deps import normalize_domain

    t = user.tenant
    domain = normalize_domain(payload.email_domain)
    if user.email.rsplit("@", 1)[1] != domain:
        raise HTTPException(status_code=400, detail="The SSO email domain must be your own email's domain")
    taken = (db.query(models.Tenant).filter(models.Tenant.sso_email_domain == domain,
                                            models.Tenant.id != t.id).first())
    if taken:
        raise HTTPException(status_code=409, detail="That email domain already uses SSO with another account")
    secret = payload.client_secret or crypto.decrypt(t.sso_client_secret)
    if not secret:
        raise HTTPException(status_code=400, detail="Client secret is required")
    try:
        sso.discover(payload.issuer.strip())
    except sso.SsoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    t.sso_issuer = payload.issuer.strip().rstrip("/")
    t.sso_client_id = payload.client_id.strip()
    t.sso_client_secret = crypto.encrypt(secret)
    t.sso_email_domain = domain
    t.sso_enforced = payload.enforced
    db.commit()
    audit.log_request(db, request, "sso.update", user,
                      {"issuer": t.sso_issuer, "domain": domain, "enforced": payload.enforced})
    return get_sso(user)


@router.delete("/api/team/sso")
def delete_sso(request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_owner)):
    t = user.tenant
    t.sso_issuer = t.sso_client_id = t.sso_client_secret = t.sso_email_domain = None
    t.sso_enforced = False
    db.commit()
    audit.log_request(db, request, "sso.delete", user)
    return {"ok": True}


@router.get("/api/auth/sso/start")
def sso_start(email: str, request: Request, db: Session = Depends(get_db)):
    auth_limit(request, "sso", limit=30)
    domain = email.lower().strip().rsplit("@", 1)[-1]
    tenant = (db.query(models.Tenant)
              .filter(models.Tenant.sso_email_domain == domain,
                      models.Tenant.sso_issuer.isnot(None)).first())
    if not tenant:
        return _fail(f"SSO isn't set up for @{domain}. Sign in with your password.")
    try:
        url, cookie = sso.start(tenant)
    except sso.SsoError as exc:
        return _fail(str(exc))
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure,
                    samesite="lax", max_age=sso.STATE_TTL, path="/api/auth/sso")
    return resp


@router.get("/api/auth/sso/callback")
def sso_callback(request: Request, code: str | None = None, state: str | None = None,
                 error: str | None = None, db: Session = Depends(get_db)):
    if error:
        return _fail(f"Your identity provider refused the sign-in ({error[:60]})")
    try:
        data = sso.read_state(request.cookies.get(COOKIE))
        if not state or not code or not secrets.compare_digest(state, data["state"]):
            raise sso.SsoError("Sign-in session mismatch: start again")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == data["tid"]).first()
        if not tenant or not tenant.sso_issuer:
            raise sso.SsoError("SSO is no longer configured for this account")
        claims = sso.finish(tenant, code, data)
    except sso.SsoError as exc:
        return _fail(str(exc))
    email = claims["email"]
    user = db.query(models.User).filter(models.User.email == email).first()
    if user and user.tenant_id != tenant.id:
        return _fail("This email belongs to a different PhishLens account")
    if user and not user.is_active:
        return _fail("This account is disabled")
    if not user:  # just-in-time provisioning: the IdP decides who gets access
        user = models.User(tenant_id=tenant.id, email=email, role="member", is_verified=True,
                           password_hash=security.hash_password(secrets.token_urlsafe(32)[:60]))
        db.add(user)
        db.commit()
        db.refresh(user)
        audit.log_request(db, request, "sso.user_provisioned", user)
    elif not user.is_verified:
        user.is_verified = True
        db.commit()
    audit.log_request(db, request, "auth.login", user, {"sso": True})
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id, version=user.token_version)
    resp = RedirectResponse("/dashboard", status_code=303)
    _set_session_cookies(resp, token)
    resp.delete_cookie(COOKIE, path="/api/auth/sso")
    return resp
