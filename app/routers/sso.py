"""SSO (OpenID Connect or SAML 2.0): tenant configuration and the sign-in flows."""
import secrets
import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, models, saml, security, sso
from ..config import settings
from ..database import get_db
from ..deps import auth_limit, get_current_user, require_owner
from .auth import _set_session_cookies

router = APIRouter(tags=["sso"])
COOKIE = "sso_state"
SAML_COOKIE = "saml_state"


class SsoConfigIn(BaseModel):
    issuer: str = Field(min_length=8, max_length=300)
    client_id: str = Field(min_length=1, max_length=300)
    client_secret: str | None = Field(default=None, max_length=1000)
    email_domain: str = Field(min_length=3, max_length=253)
    enforced: bool = False


class SamlConfigIn(BaseModel):
    metadata_xml: str | None = Field(default=None, max_length=200_000)
    entity_id: str | None = Field(default=None, max_length=500)
    sso_url: str | None = Field(default=None, max_length=1000)
    certificate: str | None = Field(default=None, max_length=20_000)
    email_domain: str = Field(min_length=3, max_length=253)
    enforced: bool = False


def _fail(message: str) -> RedirectResponse:
    resp = RedirectResponse("/login?sso_error=" + urllib.parse.quote(message), status_code=303)
    resp.delete_cookie(COOKIE, path="/api/auth/sso")
    return resp


@router.get("/api/team/sso")
def get_sso(user: models.User = Depends(get_current_user)):
    t = user.tenant
    protocol = "saml" if t.sso_protocol == "saml" else "oidc"
    return {"configured": bool(t.saml_sso_url if protocol == "saml" else t.sso_issuer),
            "protocol": protocol, "issuer": t.sso_issuer, "client_id": t.sso_client_id,
            "email_domain": t.sso_email_domain, "enforced": bool(t.sso_enforced),
            "has_secret": bool(t.sso_client_secret), "redirect_uri": sso.redirect_uri(),
            "saml_entity_id": t.saml_entity_id, "saml_sso_url": t.saml_sso_url,
            "saml_has_cert": bool(t.saml_idp_cert), "sp_entity_id": saml.sp_entity_id(),
            "acs_url": saml.acs_url()}


def _claim_domain(db: Session, user: models.User, email_domain: str) -> str:
    from ..deps import normalize_domain

    domain = normalize_domain(email_domain)
    if user.email.rsplit("@", 1)[1] != domain:
        raise HTTPException(status_code=400, detail="The SSO email domain must be your own email's domain")
    taken = (db.query(models.Tenant).filter(models.Tenant.sso_email_domain == domain,
                                            models.Tenant.id != user.tenant_id).first())
    if taken:
        raise HTTPException(status_code=409, detail="That email domain already uses SSO with another account")
    return domain


@router.put("/api/team/sso")
def set_sso(payload: SsoConfigIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(require_owner)):
    t = user.tenant
    domain = _claim_domain(db, user, payload.email_domain)
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
    t.sso_protocol = "oidc"
    t.saml_entity_id = t.saml_sso_url = t.saml_idp_cert = None
    db.commit()
    audit.log_request(db, request, "sso.update", user,
                      {"issuer": t.sso_issuer, "domain": domain, "enforced": payload.enforced})
    return get_sso(user)


@router.put("/api/team/saml")
def set_saml(payload: SamlConfigIn, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_owner)):
    from .. import webhooks

    t = user.tenant
    domain = _claim_domain(db, user, payload.email_domain)
    try:
        if payload.metadata_xml and payload.metadata_xml.strip():
            idp = saml.parse_metadata(payload.metadata_xml)
        else:
            if not (payload.entity_id and payload.sso_url and (payload.certificate or t.saml_idp_cert)):
                raise saml.SamlError("Paste the IdP metadata, or give its entity ID, sign-in URL and certificate")
            idp = {"entity_id": payload.entity_id.strip(), "sso_url": payload.sso_url.strip(),
                   "certificate": saml.load_cert(payload.certificate) if payload.certificate else t.saml_idp_cert}
    except saml.SamlError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not idp["entity_id"]:
        raise HTTPException(status_code=400, detail="The identity provider has no entity ID")
    if not idp["sso_url"].startswith("https://") or not webhooks.url_allowed(idp["sso_url"]):
        raise HTTPException(status_code=400, detail="The sign-in URL must be public https")
    t.sso_protocol = "saml"
    t.saml_entity_id, t.saml_sso_url, t.saml_idp_cert = idp["entity_id"], idp["sso_url"], idp["certificate"]
    t.sso_issuer = t.sso_client_id = t.sso_client_secret = None
    t.sso_email_domain = domain
    t.sso_enforced = payload.enforced
    db.commit()
    audit.log_request(db, request, "sso.update", user,
                      {"protocol": "saml", "entity_id": t.saml_entity_id, "domain": domain,
                       "enforced": payload.enforced})
    return get_sso(user)


@router.delete("/api/team/sso")
def delete_sso(request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_owner)):
    t = user.tenant
    t.sso_issuer = t.sso_client_id = t.sso_client_secret = t.sso_email_domain = None
    t.saml_entity_id = t.saml_sso_url = t.saml_idp_cert = t.sso_protocol = None
    t.sso_enforced = False
    db.commit()
    audit.log_request(db, request, "sso.delete", user)
    return {"ok": True}


@router.get("/api/auth/sso/start")
def sso_start(email: str, request: Request, db: Session = Depends(get_db)):
    auth_limit(request, "sso", limit=30)
    domain = email.lower().strip().rsplit("@", 1)[-1]
    tenant = db.query(models.Tenant).filter(models.Tenant.sso_email_domain == domain).first()
    if not tenant or not (tenant.sso_issuer or tenant.saml_sso_url):
        return _fail(f"SSO isn't set up for @{domain}. Sign in with your password.")
    if tenant.sso_protocol == "saml":
        url, cookie = saml.start(tenant)
        resp = RedirectResponse(url, status_code=303)
        # The IdP posts back cross-site, so the state cookie must be SameSite=None.
        resp.set_cookie(SAML_COOKIE, cookie, httponly=True, secure=settings.cookie_secure,
                        samesite="none" if settings.cookie_secure else "lax",
                        max_age=saml.STATE_TTL, path="/api/auth/saml")
        return resp
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
    resp = _complete_login(db, request, tenant, claims["email"], "oidc")
    resp.delete_cookie(COOKIE, path="/api/auth/sso")
    return resp


def _complete_login(db: Session, request: Request, tenant: models.Tenant, email: str, protocol: str):
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
    audit.log_request(db, request, "auth.login", user, {"sso": protocol})
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id, version=user.token_version,
                                         sso=True)
    resp = RedirectResponse("/dashboard", status_code=303)
    _set_session_cookies(resp, token)
    return resp


# ------------------------------------------------------------------ SAML
def _use_once(db: Session, key: str) -> None:
    """Each sign-in request can complete once, so a captured response can't be replayed."""
    from datetime import datetime

    from sqlalchemy.exc import IntegrityError

    db.add(models.RateCounter(key=key, window_start=datetime.utcnow(), count=1))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise saml.SamlError("This sign-in response was already used: start again")


@router.get("/api/auth/saml/metadata")
def saml_metadata():
    """Service-provider metadata to give the identity provider."""
    return Response(saml.sp_metadata(), media_type="application/samlmetadata+xml")


@router.post("/api/auth/saml/acs")
async def saml_acs(request: Request, db: Session = Depends(get_db)):
    auth_limit(request, "saml", limit=30)
    body = await request.body()
    if len(body) > 500_000:
        return _fail("The sign-in response is too large")
    form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    saml_response = (form.get("SAMLResponse") or [""])[0]
    relay = (form.get("RelayState") or [""])[0]
    try:
        state = saml.read_state(request.cookies.get(SAML_COOKIE))
        if not relay or not secrets.compare_digest(relay, state["relay"]):
            raise saml.SamlError("Sign-in session mismatch: start again")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == state["tid"]).first()
        if not tenant or tenant.sso_protocol != "saml" or not tenant.saml_idp_cert:
            raise saml.SamlError("SAML is no longer configured for this account")
        email = saml.parse_response(saml_response, tenant, state["rid"])
        _use_once(db, f"saml:{state['rid']}")
    except saml.SamlError as exc:
        resp = _fail(str(exc))
        resp.delete_cookie(SAML_COOKIE, path="/api/auth/saml")
        return resp
    resp = _complete_login(db, request, tenant, email, "saml")
    resp.delete_cookie(SAML_COOKIE, path="/api/auth/saml")
    return resp
