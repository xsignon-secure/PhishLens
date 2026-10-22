"""Tenant administration: API keys, team invites, webhooks, audit log, data export."""
import hashlib
import secrets
import urllib.parse
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, branding, mailer, models, schemas, tokens, webhooks
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, require_owner, require_pro_owner

router = APIRouter(prefix="/api/team", tags=["team"])


# ------------------------------------------------------------------ API keys
@router.post("/keys", status_code=201)
def create_api_key(payload: schemas.ApiKeyIn, request: Request,
                   db: Session = Depends(get_db),
                   user: models.User = Depends(require_owner)):
    raw = "plk_" + secrets.token_urlsafe(32)
    key = models.ApiKey(
        tenant_id=user.tenant_id, user_id=user.id, name=payload.name.strip(),
        key_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:12])
    db.add(key)
    db.commit()
    audit.log_request(db, request, "apikey.create", user, {"name": key.name, "prefix": key.prefix})
    # raw key is shown exactly once — we only store the hash
    return {"api_key": raw, "id": key.id, "prefix": key.prefix}


@router.get("/keys")
def list_api_keys(request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    keys = (db.query(models.ApiKey)
            .filter(models.ApiKey.tenant_id == user.tenant_id,
                    models.ApiKey.is_active.is_(True))
            .order_by(models.ApiKey.created_at.desc()).all())
    return [{"id": k.id, "name": k.name, "prefix": k.prefix,
             "created_at": k.created_at.isoformat() + "Z",
             "last_used_at": k.last_used_at.isoformat() + "Z" if k.last_used_at else None}
            for k in keys]


@router.delete("/keys/{key_id}")
def revoke_api_key(key_id: str, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_owner)):
    key = (db.query(models.ApiKey)
           .filter(models.ApiKey.id == key_id, models.ApiKey.tenant_id == user.tenant_id)
           .first())
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    audit.log_request(db, request, "apikey.revoke", user, {"prefix": key.prefix})
    return {"ok": True}


# ------------------------------------------------------------------ team
@router.get("/members")
def list_members(request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(get_current_user)):
    members = (db.query(models.User)
               .filter(models.User.tenant_id == user.tenant_id,
                       models.User.is_active.is_(True))
               .order_by(models.User.created_at).all())
    return [{"id": m.id, "email": m.email, "role": m.role,
             "is_verified": m.is_verified,
             "created_at": m.created_at.isoformat() + "Z"} for m in members]


@router.post("/invite", status_code=201)
def invite_member(payload: schemas.InviteIn, request: Request,
                  db: Session = Depends(get_db),
                  user: models.User = Depends(require_owner)):
    email = payload.email.lower().strip()
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    raw = tokens.create(db, "invite", ttl_hours=72, tenant_id=user.tenant_id,
                        extra={"email": email, "role": "member"})
    link = f"{settings.APP_URL}/signup?invite={raw}"
    mailer.send_email(
        [email], f"Join {user.tenant.name} on {settings.APP_NAME}",
        f"{user.email} invited you to join {user.tenant.name}.\n\n"
        f"Accept (expires in 72h):\n{link}")
    audit.log_request(db, request, "team.invite", user, {"email": email})
    return {"ok": True}


# ------------------------------------------------------------------ webhooks
def _validate_webhook_url(url: str) -> str:
    url = url.strip()
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise HTTPException(status_code=400, detail="Webhook URL must be http(s)")
    host = parts.hostname or ""
    if parts.scheme == "http" and not webhooks.is_local_dev_host(host):
        raise HTTPException(status_code=400, detail="Webhook URL must be https (http allowed only for localhost)")
    if not webhooks.url_allowed(url):
        raise HTTPException(status_code=400,
                            detail="Webhook host must resolve to a public address")
    return url


@router.get("/webhook")
def get_webhook(request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"url": t.webhook_url, "has_secret": bool(t.webhook_secret)}


@router.put("/webhook")
def set_webhook(payload: schemas.WebhookIn, request: Request,
                db: Session = Depends(get_db),
                user: models.User = Depends(require_owner)):
    url = _validate_webhook_url(payload.url)
    user.tenant.webhook_url = url
    user.tenant.webhook_secret = payload.secret
    db.commit()
    audit.log_request(db, request, "webhook.update", user, {"url": url})
    return {"ok": True}


@router.delete("/webhook")
def delete_webhook(request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_owner)):
    user.tenant.webhook_url = None
    user.tenant.webhook_secret = None
    db.commit()
    audit.log_request(db, request, "webhook.delete", user)
    return {"ok": True}


@router.post("/webhook/test")
def test_webhook(request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(require_owner)):
    t = user.tenant
    if not t.webhook_url or not t.webhook_secret:
        raise HTTPException(status_code=400, detail="No webhook configured")
    ok = webhooks.deliver(t.webhook_url, t.webhook_secret,
                          {"event": "webhook.test", "at": datetime.utcnow().isoformat() + "Z"})
    audit.log_request(db, request, "webhook.test", user, {"ok": ok})
    return {"ok": ok}


# ------------------------------------------------------------------ audit + export
@router.get("/audit")
def audit_log(request: Request, db: Session = Depends(get_db),
              user: models.User = Depends(require_owner), limit: int = 100):
    events = (db.query(models.AuditEvent)
              .filter(models.AuditEvent.tenant_id == user.tenant_id)
              .order_by(models.AuditEvent.created_at.desc())
              .limit(max(1, min(limit, 500))).all())
    return [{"id": e.id, "action": e.action, "detail": e.detail, "ip": e.ip,
             "user_id": e.user_id,
             "created_at": e.created_at.isoformat() + "Z"} for e in events]


@router.get("/export")
def export_data(request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(require_owner)):
    tid = user.tenant_id
    data = {
        "tenant": {"id": tid, "name": user.tenant.name, "plan": user.tenant.plan},
        "users": [{"id": u.id, "email": u.email, "role": u.role,
                   "is_verified": u.is_verified,
                   "created_at": u.created_at.isoformat() + "Z"}
                  for u in db.query(models.User).filter(models.User.tenant_id == tid).all()],
        "monitors": [{"domain": m.domain, "last_score": m.last_score,
                      "is_active": m.is_active} for m in
                     db.query(models.Monitor).filter(models.Monitor.tenant_id == tid).all()],
        "scans": [{"domain": s.domain, "score": s.score, "grade": s.grade,
                   "created_at": s.created_at.isoformat() + "Z"} for s in
                  db.query(models.Scan).filter(models.Scan.tenant_id == tid)
                  .order_by(models.Scan.created_at.desc()).limit(500).all()],
        "alerts": [{"kind": a.kind, "message": a.message,
                    "created_at": a.created_at.isoformat() + "Z"} for a in
                   db.query(models.Alert).filter(models.Alert.tenant_id == tid)
                   .order_by(models.Alert.created_at.desc()).limit(500).all()],
    }
    audit.log_request(db, request, "account.export", user)
    return data


# ------------------------------------------------------------------ white-label + alert recipients
@router.get("/branding")
def get_branding(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"brand_name": t.brand_name, "brand_color": t.brand_color,
            "report_footer": t.report_footer, "logo": branding.logo_data_url(t.brand_logo),
            "alert_emails": t.alert_emails or []}


@router.put("/branding")
def set_branding(payload: schemas.BrandingIn, request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(require_pro_owner)):
    t = user.tenant
    try:
        t.brand_color = branding.clean_color(payload.brand_color)
        if payload.logo is not None:  # None = keep, "" = remove
            t.brand_logo = branding.clean_logo(payload.logo)
    except branding.BrandingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    t.brand_name = (payload.brand_name or "").strip() or None
    t.report_footer = (payload.report_footer or "").strip() or None
    t.alert_emails = sorted({str(e).lower() for e in payload.alert_emails})
    db.commit()
    audit.log_request(db, request, "branding.update", user,
                      {"brand_name": t.brand_name, "alert_emails": len(t.alert_emails)})
    return get_branding(user)
