"""Company settings: API keys, webhooks, audit log, data export, branding,
the company's own mail server."""
import hashlib
import re
import secrets
import urllib.parse
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, branding, mailer, models, pgp, plans, schemas, webhooks
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, require_admin, require_step_up

router = APIRouter(prefix="/api/team", tags=["team"])
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


# ------------------------------------------------------------------ API keys
@router.post("/keys", status_code=201)
def create_api_key(payload: schemas.ApiKeyIn, request: Request,
                   db: Session = Depends(get_db),
                   user: models.User = Depends(require_step_up)):
    plans.require(user.tenant, "api_keys")
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
                   user: models.User = Depends(require_admin)):
    key = (db.query(models.ApiKey)
           .filter(models.ApiKey.id == key_id, models.ApiKey.tenant_id == user.tenant_id)
           .first())
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    audit.log_request(db, request, "apikey.revoke", user, {"prefix": key.prefix})
    return {"ok": True}


class PgpKeyIn(BaseModel):
    key: str


@router.get("/ruf-pgp")
def get_ruf_pgp(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"available": pgp.available(), "fingerprint": t.ruf_pgp_fingerprint,
            "key": t.ruf_pgp_key}


@router.put("/ruf-pgp")
def put_ruf_pgp(payload: PgpKeyIn, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "ruf")
    try:
        info = pgp.inspect(payload.key)
    except pgp.PgpError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    user.tenant.ruf_pgp_key, user.tenant.ruf_pgp_fingerprint = info["key"], info["fingerprint"]
    db.commit()
    audit.log_request(db, request, "ruf_pgp.update", user, {"fingerprint": info["fingerprint"]})
    return {"available": True, "fingerprint": info["fingerprint"], "uids": info["uids"], "key": info["key"]}


@router.delete("/ruf-pgp")
def delete_ruf_pgp(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    user.tenant.ruf_pgp_key = user.tenant.ruf_pgp_fingerprint = None
    db.commit()
    audit.log_request(db, request, "ruf_pgp.delete", user)
    return {"ok": True}


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
                user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "webhook")
    url = _validate_webhook_url(payload.url)
    user.tenant.webhook_url = url
    user.tenant.webhook_secret = payload.secret
    db.commit()
    audit.log_request(db, request, "webhook.update", user, {"url": url})
    return {"ok": True}


@router.delete("/webhook")
def delete_webhook(request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_admin)):
    user.tenant.webhook_url = None
    user.tenant.webhook_secret = None
    db.commit()
    audit.log_request(db, request, "webhook.delete", user)
    return {"ok": True}


@router.post("/webhook/test")
def test_webhook(request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "webhook")
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
              user: models.User = Depends(require_admin), limit: int = 100):
    events = (db.query(models.AuditEvent)
              .filter(models.AuditEvent.tenant_id == user.tenant_id,
                      models.AuditEvent.created_at >= plans.since(user.tenant, "audit_days"))
              .order_by(models.AuditEvent.created_at.desc())
              .limit(max(1, min(limit, 500))).all())
    emails = dict(db.query(models.User.id, models.User.email).filter(models.User.tenant_id == user.tenant_id).all())
    return [{"id": e.id, "action": e.action, "detail": e.detail, "ip": e.ip,
             "user_id": e.user_id, "user": emails.get(e.user_id),
             "created_at": e.created_at.isoformat() + "Z"} for e in events]


@router.get("/export")
def export_data(request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(require_step_up)):
    tid = user.tenant_id
    data = {
        "tenant": {"id": tid, "name": user.tenant.name},
        "users": [{"email": u.email, "name": u.full_name, "role": u.role, "status": u.status} for u in
                  db.query(models.User).filter(models.User.tenant_id == tid).all() if mailer.real_email(u.email)],
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
class ReportScheduleIn(BaseModel):
    schedule: Literal["off", "weekly", "monthly"]


def _schedule_out(t: models.Tenant) -> dict:
    return {"schedule": t.report_schedule or "off",
            "last_sent": t.report_sent_at.isoformat() + "Z" if t.report_sent_at else None,
            "email_configured": bool(mailer.config_for(t))}


@router.get("/report-schedule")
def get_report_schedule(user: models.User = Depends(get_current_user)):
    return _schedule_out(user.tenant)


@router.put("/report-schedule")
def set_report_schedule(payload: ReportScheduleIn, request: Request, db: Session = Depends(get_db),
                        user: models.User = Depends(require_admin)):
    if payload.schedule != "off":  # turning it off is always allowed
        plans.require(user.tenant, "scheduled_reports")
    user.tenant.report_schedule = payload.schedule
    db.commit()
    audit.log_request(db, request, "reports.schedule", user, {"schedule": payload.schedule})
    return _schedule_out(user.tenant)


@router.post("/report-schedule/send-now")
def send_report_now(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    """Send the scheduled report right away (to check what it looks like)."""
    plans.require(user.tenant, "scheduled_reports")
    from .. import scheduled_reports
    if not mailer.config_for(user.tenant):
        raise HTTPException(status_code=503, detail="Email is not set up on this server")
    rate_limit(request, f"report-now:{user.tenant_id}", 5)
    if not db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id,
                                           models.Monitor.is_active.is_(True)).first():
        raise HTTPException(status_code=400, detail="Monitor a domain first")
    if not scheduled_reports.send(db, user.tenant):
        raise HTTPException(status_code=502, detail="The email could not be sent")
    audit.log_request(db, request, "reports.send_now", user)
    return _schedule_out(user.tenant)


@router.get("/branding")
def get_branding(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"brand_name": t.brand_name, "brand_color": t.brand_color,
            "report_footer": t.report_footer, "logo": branding.logo_data_url(t.brand_logo),
            "alert_emails": t.alert_emails or []}


@router.put("/branding")
def set_branding(payload: schemas.BrandingIn, request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(require_admin)):
    # Extra alert addresses are in every plan; your own name, colour and logo are MSP.
    if payload.brand_name or payload.brand_color or payload.report_footer or payload.logo:
        plans.require(user.tenant, "white_label")
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


# ------------------------------------------------------------------ the company's own mail server
class SmtpIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int
    security: Literal["starttls", "ssl"] = "starttls"
    username: str = Field(default="", max_length=320)
    # Blank keeps the saved password: the form never gets it back.
    password: str = Field(default="", max_length=500)
    from_address: str = Field(min_length=3, max_length=320)
    from_name: str = Field(default="", max_length=100)

    model_config = {"extra": "forbid"}


def _smtp_out(t: models.Tenant) -> dict:
    c = t.smtp or {}
    return {"configured": bool(c.get("host")), "host": c.get("host"), "port": c.get("port"),
            "security": c.get("security", "starttls"), "username": c.get("username") or "",
            "has_password": bool(c.get("password")), "from_address": c.get("from_address"),
            "from_name": c.get("from_name") or "", "server_fallback": mailer.is_configured(),
            "welcome_subject": t.welcome_subject or "", "welcome_message": t.welcome_message or ""}


@router.get("/smtp")
def get_smtp(user: models.User = Depends(require_admin)):
    return _smtp_out(user.tenant)


@router.put("/smtp")
def set_smtp(payload: SmtpIn, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_step_up)):
    from .. import crypto
    host = normalize_domain(payload.host)
    if payload.port not in mailer.SMTP_PORTS:
        raise HTTPException(status_code=400, detail="Use port 587, 465, 25 or 2525")
    sender = payload.from_address.strip().lower()
    if not EMAIL_RE.match(sender):
        raise HTTPException(status_code=400, detail="Enter a valid from address")
    old = user.tenant.smtp or {}
    password = crypto.encrypt(payload.password) if payload.password else (
        old.get("password") if old.get("host") == host and old.get("username") == payload.username.strip() else None)
    user.tenant.smtp = {"host": host, "port": payload.port, "security": payload.security,
                        "username": payload.username.strip(), "password": password,
                        "from_address": sender, "from_name": payload.from_name.strip() or None}
    db.commit()
    audit.log_request(db, request, "smtp.update", user, {"host": host, "from": sender, "severity": "high"})
    return _smtp_out(user.tenant)


@router.delete("/smtp")
def delete_smtp(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_step_up)):
    user.tenant.smtp = None
    db.commit()
    audit.log_request(db, request, "smtp.delete", user, {"severity": "high"})
    return _smtp_out(user.tenant)


@router.post("/smtp/test")
def test_smtp(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    """Send a test email to yourself through the company's mail server."""
    cfg = mailer.tenant_config(user.tenant)
    if not cfg:
        raise HTTPException(status_code=400, detail="Save your mail server first")
    rate_limit(request, f"smtp-test:{user.tenant_id}", 10)
    try:
        mailer.deliver(cfg, mailer.build_message(
            cfg, [user.email], "Test email",
            f"This test came from {cfg['from_address']} through {cfg['host']}.\n"
            f"Login details for new users will be sent the same way.\n"))
    except mailer.SmtpError as exc:
        audit.log_request(db, request, "smtp.test_failed", user, {"error": str(exc)[:200]})
        raise HTTPException(status_code=502, detail=str(exc))
    audit.log_request(db, request, "smtp.test", user)
    return {"ok": True, "to": user.email}


class WelcomeIn(BaseModel):
    subject: str = Field(default="", max_length=200)
    message: str = Field(default="", max_length=2000)

    model_config = {"extra": "forbid"}


@router.put("/welcome-email")
def set_welcome_email(payload: WelcomeIn, request: Request, db: Session = Depends(get_db),
                      user: models.User = Depends(require_admin)):
    """Wording for the login-details email. Plain text; the login link,
    email and temporary password are always added by PhishLens."""
    user.tenant.welcome_subject = payload.subject.replace("\r", " ").replace("\n", " ").strip() or None
    user.tenant.welcome_message = payload.message.strip() or None
    db.commit()
    audit.log_request(db, request, "smtp.welcome_email", user)
    return _smtp_out(user.tenant)


# ------------------------------------------------------------------ plan
@router.get("/plan")
def get_plan(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """The company's plan, its limits and what is used, for the dashboard."""
    from .users import _seats
    usage = {
        "monitors": db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id,
                                                    models.Monitor.is_active.is_(True)).count(),
        "users": _seats(db, user.tenant_id),
        "dmarc_domains": db.query(models.DmarcReport.domain)
                           .filter(models.DmarcReport.tenant_id == user.tenant_id).distinct().count(),
    }
    return plans.summary(user.tenant, usage)
