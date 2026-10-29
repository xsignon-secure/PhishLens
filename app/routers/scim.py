"""SCIM 2.0 user provisioning (RFC 7643/7644) for Okta, Microsoft Entra ID,
OneLogin, JumpCloud and others: the identity provider adds, updates and
deactivates team members. Users only; groups aren't supported.

Auth is a per-team bearer token created on the dashboard (docs/SCIM.md).
Provisioned users are members who sign in with SSO (or reset a password).
Owners are managed in PhishLens, so SCIM can't deactivate or rename them."""
import hashlib
import re
import secrets
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from .. import audit, models, security
from ..config import settings
from ..database import get_db
from ..deps import rate_limit, require_owner

router = APIRouter(tags=["scim"])
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MEDIA = "application/scim+json"
MAX_COUNT = 200
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FILTER_RE = re.compile(r'^\s*(userName|emails(?:\[type eq "work"\])?\.value|externalId|id)\s+eq\s+"([^"]*)"\s*$',
                        re.IGNORECASE)


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        self.status, self.detail, self.scim_type = status, detail, scim_type


def error_response(exc: ScimError) -> JSONResponse:
    body = {"schemas": [ERROR_SCHEMA], "status": str(exc.status), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(body, status_code=exc.status, media_type=MEDIA)


def _json(data, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, media_type=MEDIA)


def _base() -> str:
    return settings.APP_URL.rstrip("/") + "/scim/v2"


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def scim_tenant(request: Request, db: Session = Depends(get_db)) -> models.Tenant:
    auth = request.headers.get("authorization") or ""
    raw = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    tenant = (db.query(models.Tenant).filter(models.Tenant.scim_token_hash == hash_token(raw)).first()
              if raw.startswith("scim_") else None)
    if not tenant:
        raise ScimError(401, "Invalid or missing SCIM token")
    try:
        rate_limit(request, f"scim:{tenant.id}", 3000)
    except HTTPException:
        raise ScimError(429, "Too many requests") from None
    return tenant


def _user(u: models.User) -> dict:
    return {
        "schemas": [USER_SCHEMA], "id": u.id, "userName": u.email, "active": bool(u.is_active),
        "emails": [{"value": u.email, "type": "work", "primary": True}],
        "roles": [{"value": u.role, "primary": True}],
        "meta": {"resourceType": "User", "created": u.created_at.isoformat() + "Z",
                 "lastModified": u.created_at.isoformat() + "Z", "location": f"{_base()}/Users/{u.id}"},
    }


def _get(db: Session, tenant: models.Tenant, user_id: str) -> models.User:
    u = db.query(models.User).filter(models.User.id == user_id, models.User.tenant_id == tenant.id).first()
    if not u:
        raise ScimError(404, "User not found")
    return u


def _email_from(body: dict) -> str | None:
    email = body.get("userName")
    if not email:
        emails = body.get("emails") or []
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary")), emails[0] if emails else None)
        email = primary.get("value") if isinstance(primary, dict) else None
    return str(email).strip().lower() if email else None


def _bool(value) -> bool:
    # Entra ID sends "True"/"False" strings in PATCH operations.
    return value.strip().lower() == "true" if isinstance(value, str) else bool(value)


def _apply(db: Session, request: Request, tenant: models.Tenant, u: models.User, *,
           email: str | None = None, active: bool | None = None) -> None:
    if email is not None and email != u.email:
        if u.role == "owner":
            raise ScimError(400, "Owners are managed in PhishLens", "mutability")
        if not _EMAIL_RE.match(email) or len(email) > 320:
            raise ScimError(400, "userName must be an email address", "invalidValue")
        if db.query(models.User).filter(models.User.email == email).first():
            raise ScimError(409, "userName is already in use", "uniqueness")
        u.email = email
        u.token_version = (u.token_version or 0) + 1
    if active is not None and active != u.is_active:
        if u.role == "owner" and not active:
            raise ScimError(400, "Owners are managed in PhishLens", "mutability")
        u.is_active = active
        if not active:
            u.token_version = (u.token_version or 0) + 1  # signs them out everywhere
    db.commit()
    audit.log(db, "scim.user_update", tenant_id=tenant.id, detail={"user": u.email, "active": u.is_active},
              ip=request.client.host if request.client else None)


# ------------------------------------------------------------------ discovery
@router.get("/scim/v2/ServiceProviderConfig")
def service_provider_config():
    return _json({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/xsignon-secure/PhishLens/blob/main/docs/SCIM.md",
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                   "description": "Team SCIM token from the PhishLens dashboard", "primary": True}],
    })


@router.get("/scim/v2/ResourceTypes")
def resource_types():
    return _json({"schemas": [LIST_SCHEMA], "totalResults": 1, "startIndex": 1, "itemsPerPage": 1, "Resources": [{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
        "endpoint": "/Users", "schema": USER_SCHEMA}]})


@router.get("/scim/v2/Schemas")
def schemas_():
    attr = lambda name, typ="string", **kw: {"name": name, "type": typ, "multiValued": False, "required": False,
                                            "mutability": "readWrite", "returned": "default", **kw}
    return _json({"schemas": [LIST_SCHEMA], "totalResults": 1, "startIndex": 1, "itemsPerPage": 1, "Resources": [{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], "id": USER_SCHEMA, "name": "User",
        "attributes": [attr("userName", required=True, uniqueness="server"), attr("active", "boolean"),
                       {**attr("emails", "complex"), "multiValued": True}]}]})


# ------------------------------------------------------------------ users
@router.get("/scim/v2/Users")
def list_users(filter: str | None = None, startIndex: int = 1, count: int = 100,
               db: Session = Depends(get_db), tenant: models.Tenant = Depends(scim_tenant)):
    q = db.query(models.User).filter(models.User.tenant_id == tenant.id)
    if filter:
        m = _FILTER_RE.match(filter)
        if not m:
            raise ScimError(400, "Only 'userName eq \"...\"' style filters are supported", "invalidFilter")
        attr, value = m.group(1).lower(), m.group(2)
        if attr == "externalid":
            q = q.filter(models.User.id.is_(None))  # not stored: never matches
        elif attr == "id":
            q = q.filter(models.User.id == value)
        else:
            q = q.filter(models.User.email == value.strip().lower())
    total = q.count()
    start, count = max(1, startIndex), max(0, min(count, MAX_COUNT))
    rows = q.order_by(models.User.created_at, models.User.id).offset(start - 1).limit(count).all()
    return _json({"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start,
                  "itemsPerPage": len(rows), "Resources": [_user(u) for u in rows]})


@router.get("/scim/v2/Users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db), tenant: models.Tenant = Depends(scim_tenant)):
    return _json(_user(_get(db, tenant, user_id)))


@router.post("/scim/v2/Users")
def create_user(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                tenant: models.Tenant = Depends(scim_tenant)):
    email = _email_from(body)
    if not email or not _EMAIL_RE.match(email) or len(email) > 320:
        raise ScimError(400, "userName must be an email address", "invalidValue")
    if db.query(models.User).filter(models.User.email == email).first():
        raise ScimError(409, "userName is already in use", "uniqueness")
    u = models.User(tenant_id=tenant.id, email=email, role="member", is_verified=True,
                    is_active=_bool(body.get("active", True)),
                    password_hash=security.hash_password(secrets.token_urlsafe(32)[:60]))
    db.add(u)
    db.commit()
    db.refresh(u)
    audit.log(db, "scim.user_create", tenant_id=tenant.id, detail={"user": email},
              ip=request.client.host if request.client else None)
    return _json(_user(u), 201)


@router.put("/scim/v2/Users/{user_id}")
def replace_user(user_id: str, request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                 tenant: models.Tenant = Depends(scim_tenant)):
    u = _get(db, tenant, user_id)
    _apply(db, request, tenant, u, email=_email_from(body),
           active=_bool(body["active"]) if "active" in body else None)
    return _json(_user(u))


@router.patch("/scim/v2/Users/{user_id}")
def patch_user(user_id: str, request: Request, body: dict = Body(...), db: Session = Depends(get_db),
               tenant: models.Tenant = Depends(scim_tenant)):
    u = _get(db, tenant, user_id)
    ops = body.get("Operations")
    if not isinstance(ops, list):
        raise ScimError(400, "Operations must be a list", "invalidSyntax")
    email = active = None
    for op in ops:
        if not isinstance(op, dict) or str(op.get("op", "")).lower() not in ("replace", "add"):
            continue  # remove of an optional attribute: nothing we store
        path, value = (op.get("path") or "").strip(), op.get("value")
        changes = value if not path and isinstance(value, dict) else {path: value}
        for key, val in changes.items():
            key = key.lower()
            if key == "active":
                active = _bool(val)
            elif key == "username":
                email = str(val).strip().lower()
            elif key.startswith("emails") and val:
                email = _email_from({"emails": val if isinstance(val, list) else [{"value": val, "primary": True}]})
    _apply(db, request, tenant, u, email=email, active=active)
    return _json(_user(u))


@router.delete("/scim/v2/Users/{user_id}")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db),
                tenant: models.Tenant = Depends(scim_tenant)):
    # Deactivated, not deleted: their audit trail stays, and the IdP can reactivate.
    _apply(db, request, tenant, _get(db, tenant, user_id), active=False)
    return Response(status_code=204)


@router.get("/scim/v2/Groups")
def list_groups(tenant: models.Tenant = Depends(scim_tenant)):
    return _json({"schemas": [LIST_SCHEMA], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []})


# ------------------------------------------------------------------ token (dashboard)
@router.get("/api/team/scim")
def scim_status(user: models.User = Depends(require_owner)):
    return {"enabled": bool(user.tenant.scim_token_hash), "base_url": _base()}


@router.post("/api/team/scim/token")
def scim_new_token(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_owner)):
    raw = "scim_" + secrets.token_urlsafe(32)
    user.tenant.scim_token_hash = hash_token(raw)
    db.commit()
    audit.log_request(db, request, "scim.token_create", user)
    # Shown once: only the hash is stored. A new token replaces the old one.
    return {"token": raw, "base_url": _base(), "created_at": datetime.utcnow().isoformat() + "Z"}


@router.delete("/api/team/scim/token")
def scim_delete_token(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_owner)):
    user.tenant.scim_token_hash = None
    db.commit()
    audit.log_request(db, request, "scim.token_delete", user)
    return {"ok": True}
