"""Phishing simulations: domain proof, campaigns, results, and the page a
recipient sees after clicking. Safeguards are described in app/simulations.py."""
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, mailer, models, plans, simulations as sims
from ..database import get_db
from ..deps import client_ip, get_current_user, normalize_domain, rate_limit, require_admin, require_owner, \
    require_step_up
from .pages import templates

router = APIRouter(tags=["simulations"])


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _campaign_out(db, c: models.SimCampaign) -> dict:
    return {"id": c.id, "name": c.name, "template": c.template,
            "template_name": sims.TEMPLATES.get(c.template, {}).get("name", c.template),
            "status": c.status, "authorized_by": c.authorized_by, "created_at": _iso(c.created_at),
            "finished_at": _iso(c.finished_at), **sims.stats(db, c)}


@router.get("/api/simulations")
def overview(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    t = user.tenant
    plans.require(t, "simulations")
    rows = (db.query(models.SimCampaign).filter(models.SimCampaign.tenant_id == t.id)
            .order_by(models.SimCampaign.created_at.desc()).limit(50).all())
    return {
        "templates": [{"key": k, "name": v["name"], "difficulty": v["difficulty"], "from_name": v["from_name"],
                       "subject": v["subject"]} for k, v in sims.TEMPLATES.items()],
        "mail_server": bool(mailer.tenant_config(t)),
        "from_address": (t.smtp or {}).get("from_address"),
        "verify": {"name": sims.TXT_LABEL + ".<domain>", "value": sims.verify_value(t.id)},
        "domains": [{"domain": d, **v} for d, v in sorted(sims.verified(t).items())],
        "campaigns": [_campaign_out(db, c) for c in rows],
        "max_recipients": sims.MAX_RECIPIENTS,
    }


class DomainIn(BaseModel):
    domain: str = Field(..., max_length=253)


@router.post("/api/simulations/domains")
def add_domain(body: DomainIn, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_owner)):
    t = user.tenant
    plans.require(t, "simulations")
    rate_limit(request, f"sim-domain:{t.id}", 30)
    domain = normalize_domain(body.domain)
    how = sims.proof(t, domain)
    if not how:
        raise HTTPException(status_code=400, detail=(
            f"Add a TXT record at {sims.TXT_LABEL}.{domain} with the value {sims.verify_value(t.id)} "
            "(or connect the Microsoft 365 / Google Workspace check), then try again."))
    domains = sims.verified(t)
    domains[domain] = {"how": how, "at": _iso(datetime.utcnow())}
    t.sim_domains = domains
    db.commit()
    audit.log_request(db, request, "simulation.domain_verified", user, {"domain": domain, "how": how})
    return {"domain": domain, "how": how}


@router.delete("/api/simulations/domains/{domain}")
def remove_domain(domain: str, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_owner)):
    t = user.tenant
    domains = sims.verified(t)
    domains.pop(domain.lower(), None)
    t.sim_domains = domains
    db.commit()
    audit.log_request(db, request, "simulation.domain_removed", user, {"domain": domain})
    return {"ok": True}


class CampaignIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    template: str
    recipients: str = Field(..., max_length=100_000)
    authorized: bool = False


@router.post("/api/simulations", status_code=201)
def launch(body: CampaignIn, request: Request, background: BackgroundTasks, db: Session = Depends(get_db),
           user: models.User = Depends(require_step_up)):
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Only an owner can launch a phishing simulation")
    t = user.tenant
    plans.require(t, "simulations")
    if not body.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorised to test these people")
    if body.template not in sims.TEMPLATES:
        raise HTTPException(status_code=400, detail="Unknown template")
    if not mailer.tenant_config(t):
        raise HTTPException(status_code=400, detail=(
            "Connect your company's own mail server first (Users → Email server). "
            "Simulations are never sent through this service's mail server."))
    try:
        emails = sims.parse_recipients(body.recipients)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not emails:
        raise HTTPException(status_code=400, detail="Add at least one recipient")
    if len(emails) > sims.MAX_RECIPIENTS:
        raise HTTPException(status_code=400, detail=f"At most {sims.MAX_RECIPIENTS} recipients per simulation")
    now = datetime.utcnow()
    if sims.campaigns_today(db, t.id, now) >= sims.MAX_PER_DAY:
        raise HTTPException(status_code=429, detail=f"At most {sims.MAX_PER_DAY} simulations a day")
    # Proof of control is re-checked now: a removed TXT record stops new tests.
    domains = sims.verified(t)
    proved = {d for d in domains if sims.proof(t, d)}
    lapsed = set(domains) - proved
    if lapsed:
        t.sim_domains = {d: v for d, v in domains.items() if d in proved}
        db.commit()
    outside = sorted({e.rsplit("@", 1)[1] for e in emails if not sims.recipient_domain_ok(e, proved)})
    if outside:
        raise HTTPException(status_code=400, detail=(
            "These domains aren't verified for simulations: " + ", ".join(outside[:10])))
    c = models.SimCampaign(tenant_id=t.id, name=body.name.strip(), template=body.template, status="sending",
                           authorized_by=user.email, authorized_at=now, created_at=now)
    db.add(c)
    db.flush()
    for e in emails:
        db.add(models.SimRecipient(tenant_id=t.id, campaign_id=c.id, email=e, token=sims.new_token()))
    db.commit()
    audit.log_request(db, request, "simulation.launched", user,
                      {"campaign": c.id, "template": c.template, "recipients": len(emails),
                       "authorized": True})
    background.add_task(sims.send_in_background, c.id)
    return _campaign_out(db, c)


def _own_campaign(db, user, cid) -> models.SimCampaign:
    c = db.get(models.SimCampaign, cid)
    if not c or c.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Not found")
    return c


@router.get("/api/simulations/{cid}")
def detail(cid: str, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    c = _own_campaign(db, user, cid)
    rows = (db.query(models.SimRecipient).filter(models.SimRecipient.campaign_id == c.id)
            .order_by(models.SimRecipient.email).all())
    return {**_campaign_out(db, c), "people": [
        {"email": r.email, "sent_at": _iso(r.sent_at), "error": r.error, "clicked_at": _iso(r.clicked_at),
         "reported_at": _iso(r.reported_at)} for r in rows]}


@router.delete("/api/simulations/{cid}")
def delete(cid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_owner)):
    c = _own_campaign(db, user, cid)
    db.query(models.SimRecipient).filter(models.SimRecipient.campaign_id == c.id).delete()
    db.delete(c)
    db.commit()
    audit.log_request(db, request, "simulation.deleted", user, {"campaign": cid})
    return {"ok": True}


# ------------------------------------------------------------------ recipient side
@router.get("/s/{token}", response_class=HTMLResponse)
def landing(token: str, request: Request, db: Session = Depends(get_db)):
    r = sims.recipient_for_token(db, token)
    if not r:
        return HTMLResponse("<!doctype html><title>Not found</title><p>This link has expired.</p>", status_code=404)
    c = db.get(models.SimCampaign, r.campaign_id)
    tenant = db.get(models.Tenant, r.tenant_id)
    tpl = sims.TEMPLATES.get(c.template if c else "", {})
    resp = templates.TemplateResponse(request, "sim_landing.html", {
        "request": request, "company": tenant.brand_name or tenant.name, "subject": tpl.get("subject", ""),
        "signs": tpl.get("signs", []), "token": token, "report_button": bool(tenant.report_token_hash)})
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Robots-Tag"] = "noindex"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
        "img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
    return resp


@router.post("/s/{token}/seen")
def seen(token: str, request: Request, db: Session = Depends(get_db)):
    """Called by the landing page's script: link scanners that only fetch the
    URL don't run it, so they don't count as a click."""
    rate_limit(request, f"sim-seen:{client_ip(request)}", 120)
    r = sims.recipient_for_token(db, token)
    if r and r.sent_at and not r.clicked_at:
        r.clicked_at = datetime.utcnow()
        db.commit()
    return Response(status_code=204)
