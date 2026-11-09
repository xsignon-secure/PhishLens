"""DMARC enforcement autopilot: switch it on per domain, see what it did,
check now, step back, resume."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, autopilot, dns_providers, hosted, models
from ..database import get_db
from ..deps import get_current_user, normalize_domain, require_admin
from .hosted import _tenant_domains

router = APIRouter(prefix="/api/autopilot", tags=["autopilot"])


def _out(db: Session, tenant: models.Tenant, ap: models.DmarcAutopilot | None, domain: str) -> dict:
    base = {"domain": domain, "mode": autopilot.mode(db, tenant, domain)}
    if not ap:
        return {**base, "enabled": False, "target": "reject", "status": None, "message": None, "history": []}
    return {**base, "enabled": ap.enabled, "target": ap.target, "status": ap.status, "message": ap.message,
            "last_step_at": ap.last_step_at.isoformat() + "Z" if ap.last_step_at else None,
            "last_checked_at": ap.last_checked_at.isoformat() + "Z" if ap.last_checked_at else None,
            "history": list(reversed(ap.history or []))}


def _get(db: Session, user: models.User, domain: str) -> models.DmarcAutopilot | None:
    return db.query(models.DmarcAutopilot).filter_by(tenant_id=user.tenant_id, domain=domain).first()


def _need(db, user, domain) -> models.DmarcAutopilot:
    ap = _get(db, user, domain)
    if not ap:
        raise HTTPException(status_code=404, detail="Autopilot isn't set up for this domain")
    return ap


@router.get("/{domain}")
def get_autopilot(domain: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    domain = normalize_domain(domain)
    return _out(db, user.tenant, _get(db, user, domain), domain)


class AutopilotIn(BaseModel):
    enabled: bool
    target: str = Field(default="reject", pattern="^(quarantine|reject)$")


@router.put("/{domain}")
def set_autopilot(domain: str, body: AutopilotIn, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_admin)):
    domain = normalize_domain(domain)
    if domain not in _tenant_domains(db, user.tenant_id):
        raise HTTPException(status_code=400, detail="Scan or monitor this domain first")
    if body.enabled and not autopilot.mode(db, user.tenant, domain):
        raise HTTPException(status_code=400, detail="Autopilot needs hosted DMARC or a connected DNS provider "
                                                    "so it can change the record")
    ap = _get(db, user, domain)
    if not ap:
        ap = models.DmarcAutopilot(tenant_id=user.tenant_id, domain=domain, history=[])
        db.add(ap)
    ap.enabled, ap.target = body.enabled, body.target
    if body.enabled and ap.status == "paused":
        ap.status = "watching"
    db.commit()
    audit.log_request(db, request, "autopilot.set", user, {"domain": domain, "enabled": body.enabled,
                                                          "target": body.target})
    if body.enabled:
        autopilot.check(db, ap)
    return _out(db, user.tenant, ap, domain)


@router.post("/{domain}/check")
def check_now(domain: str, request: Request, db: Session = Depends(get_db),
              user: models.User = Depends(require_admin)):
    domain = normalize_domain(domain)
    ap = _need(db, user, domain)
    if not ap.enabled or ap.status == "paused":
        raise HTTPException(status_code=409, detail="Autopilot is off or paused for this domain")
    d = autopilot.check(db, ap)
    audit.log_request(db, request, "autopilot.check", user, {"domain": domain, "action": d["action"]})
    return {**_out(db, user.tenant, ap, domain), "decision": d}


@router.post("/{domain}/step-back")
def step_back(domain: str, request: Request, db: Session = Depends(get_db),
              user: models.User = Depends(require_admin)):
    """Undo the last tightening by hand: one level back, and pause."""
    domain = normalize_domain(domain)
    ap = _need(db, user, domain)
    try:
        _, p = autopilot.current(db, user.tenant, domain)
        if p not in autopilot.LEVELS or p == "none":
            raise HTTPException(status_code=409, detail="Already at p=none")
        to = autopilot.LEVELS[autopilot.LEVELS.index(p) - 1]
        res = autopilot.set_policy(db, user.tenant, domain, to)
    except (autopilot.AutopilotError, dns_providers.DnsProviderError, hosted.HostedError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    from datetime import datetime
    now = datetime.utcnow()
    autopilot._record(ap, p, to, f"Stepped back by {user.email}", res["via"], res["change_id"], now)
    ap.last_step_at, ap.status = now, "paused"
    ap.message = f"Stepped back to p={to} by {user.email}. Resume when you're ready."
    db.commit()
    audit.log_request(db, request, "autopilot.step_back", user, {"domain": domain, "to": to})
    return _out(db, user.tenant, ap, domain)
