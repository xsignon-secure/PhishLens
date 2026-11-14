"""Phishing report inbox, AI triage, and takedown tracking."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import assistant, audit, models, phish_reports, simulations, takedowns
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, require_admin

router = APIRouter(prefix="/api/phish-reports", tags=["phishing reports"])


def _out(r: models.PhishReport, full: bool = False) -> dict:
    out = {"id": r.id, "subject": r.subject, "sender": r.sender, "verdict": r.verdict, "score": r.score,
           "status": r.status, "reported_by": r.reported_by, "created_at": r.created_at.isoformat() + "Z",
           "links": [{"url": x.get("url"), "domain": x.get("domain"), "verdict": x.get("verdict")}
                     for x in r.links or []], "ai": r.ai}
    if full:
        out["header"] = r.header
        out["links"] = r.links or []
    return out


@router.post("", status_code=201)
async def report(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Send the suspicious email as the request body (raw .eml, or a message
    that has it attached). Anyone in the company can report."""
    rate_limit(request, f"phish-report:{user.tenant_id}", 300)
    return ingest(db, request, user.tenant, user.email, await request.body(), user)


def ingest(db: Session, request: Request, tenant: models.Tenant, reporter: str, blob: bytes,
           user: models.User | None = None, source: str = "upload") -> dict:
    """Triage a reported email and store it (dashboard upload or report button)."""
    try:
        parsed = phish_reports.parse(blob)
    except phish_reports.ReportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sim = simulations.match_report(db, tenant.id, parsed)
    if sim is not None:
        # One of the company's own phishing tests: count it as reported and
        # don't open an incident or takedowns for it.
        if not sim.reported_at:
            sim.reported_at = datetime.utcnow()
            db.commit()
        audit.log_request(db, request, "simulation.reported", user, {"campaign": sim.campaign_id, "source": source})
        return {"id": sim.id, "verdict": "simulation", "simulation": True,
                "message": "This was a phishing test from your IT team. Well done for reporting it!"}
    result = phish_reports.triage(parsed)
    ai = phish_reports.ai_triage(assistant.config(tenant), parsed, result)
    row = models.PhishReport(tenant_id=tenant.id, reported_by=reporter, subject=parsed["subject"],
                             sender=parsed["from"], verdict=result["verdict"], score=result["score"],
                             header=result["header"], links=result["links"], ai=ai)
    db.add(row)
    db.commit()
    audit.log_request(db, request, "phish.report", user, {"verdict": row.verdict, "source": source,
                                                          "reporter": reporter})
    opened = _auto_takedowns(db, tenant, row)
    out = _out(row, full=True)
    out["takedowns_opened"] = [t.domain for t in opened]
    return out


AUTO_TAKEDOWN_LIMIT = 3


def _own_domains(db: Session, tenant_id: str) -> set[str]:
    return {d for (d,) in db.query(models.Monitor.domain).filter(models.Monitor.tenant_id == tenant_id).all()}


def _auto_takedowns(db: Session, tenant: models.Tenant, row: models.PhishReport) -> list[models.Takedown]:
    """Open takedown drafts for the phishing links of a report the rule-based
    checks judged phishing. Drafts only: a person reviews and sends them."""
    if row.verdict not in ("likely phishing", "dangerous"):
        return []
    own = _own_domains(db, tenant.id)
    opened = []
    for link in row.links or []:
        dom = link.get("domain")
        if (not dom or link.get("verdict") not in ("likely phishing", "dangerous")
                or dom in own or any(dom.endswith("." + o) for o in own)):
            continue
        try:
            opened.append(takedowns.create(db, tenant, dom, link.get("url"), _evidence(db, tenant.id, dom, row),
                                           report_id=row.id, created_by="triage", auto=True))
        except Exception:
            db.rollback()  # RDAP lookups are best-effort; the report itself is saved
        if len(opened) >= AUTO_TAKEDOWN_LIMIT:
            break
    return opened


def _evidence(db: Session, tenant_id: str, domain: str, r: models.PhishReport | None) -> list[str]:
    evidence = []
    if r is not None:
        evidence.append(f"Reported by an employee on {r.created_at:%Y-%m-%d}: subject \"{r.subject}\" from {r.sender}")
        for link in r.links or []:
            if link.get("domain") == domain or (link.get("url") and domain in link["url"]):
                evidence += [s["text"] for s in link.get("signals") or []][:5]
                evidence += [f"Listed by {f['source']}" for f in link.get("feeds") or [] if f.get("listed")]
        evidence += [f["text"] for f in (r.header or {}).get("findings") or [] if f.get("level") == "fail"][:3]
        if r.ai and r.ai.get("impersonates"):
            evidence.append(f"Impersonates {r.ai['impersonates']}")
    for m in db.query(models.Monitor).filter(models.Monitor.tenant_id == tenant_id).all():
        if domain in (m.lookalikes or []):
            evidence.append(f"Lookalike of our domain {m.domain}, found by PhishLens monitoring")
    return evidence


@router.get("")
def list_reports(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (db.query(models.PhishReport).filter(models.PhishReport.tenant_id == user.tenant_id)
            .order_by(models.PhishReport.created_at.desc()).limit(200).all())
    return [_out(r) for r in rows]


# ------------------------------------------------------------------ takedowns
class TakedownIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    url: str | None = Field(default=None, max_length=2000)
    report_id: str | None = None


class SendIn(BaseModel):
    netcraft: bool = False
    apwg: bool = False


class TakedownStatusIn(BaseModel):
    status: str = Field(pattern="^(sent|closed)$")


def _takedown(db: Session, user: models.User, tid: str) -> models.Takedown:
    row = (db.query(models.Takedown)
           .filter(models.Takedown.id == tid, models.Takedown.tenant_id == user.tenant_id).first())
    if not row:
        raise HTTPException(status_code=404, detail="Takedown not found")
    return row


@router.get("/takedowns")
def list_takedowns(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (db.query(models.Takedown).filter(models.Takedown.tenant_id == user.tenant_id)
            .order_by(models.Takedown.created_at.desc()).limit(200).all())
    return [takedowns.out(t) for t in rows]


@router.post("/takedowns", status_code=201)
def open_takedown(body: TakedownIn, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_admin)):
    """Start tracking a takedown: writes the abuse report draft (or returns
    the open one for this domain)."""
    rate_limit(request, f"takedown:{user.tenant_id}", 60)
    domain = normalize_domain(body.domain)
    report = _get(db, user, body.report_id) if body.report_id else None
    row = takedowns.create(db, user.tenant, domain, body.url, _evidence(db, user.tenant_id, domain, report),
                           report_id=report.id if report else None, created_by=user.email)
    audit.log_request(db, request, "phish.takedown_open", user, {"domain": domain})
    return takedowns.out(row)


@router.post("/takedowns/{tid}/send")
def send_takedown(tid: str, body: SendIn, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_admin)):
    rate_limit(request, f"takedown-send:{user.tenant_id}", 30)
    row = _takedown(db, user, tid)
    try:
        takedowns.send(db, row, user, netcraft=body.netcraft, apwg=body.apwg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit.log_request(db, request, "phish.takedown_send", user,
                      {"domain": row.domain, "netcraft": body.netcraft, "apwg": body.apwg})
    return takedowns.out(row)


@router.post("/takedowns/{tid}/check")
def check_takedown(tid: str, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    rate_limit(request, f"takedown-check:{user.tenant_id}", 60)
    row = _takedown(db, user, tid)
    takedowns.record_check(db, row, takedowns.check_live(row.domain, row.url))
    return takedowns.out(row)


@router.patch("/takedowns/{tid}")
def set_takedown_status(tid: str, body: TakedownStatusIn, request: Request, db: Session = Depends(get_db),
                        user: models.User = Depends(require_admin)):
    """"sent" when you sent the draft from your own mail app; "closed" to stop tracking."""
    row = _takedown(db, user, tid)
    if body.status == "sent" and row.status == "draft":
        row.status, row.sent_at = "sent", datetime.utcnow()
        row.submissions = list(row.submissions or []) + [
            {"target": ", ".join((row.draft or {}).get("to") or []) or "manual", "at": datetime.utcnow().isoformat() + "Z",
             "ok": True, "detail": f"Sent by {user.email} from their own mail"}]
    elif body.status == "closed":
        row.status = "closed"
    db.commit()
    audit.log_request(db, request, "phish.takedown_status", user, {"domain": row.domain, "status": row.status})
    return takedowns.out(row)


def _get(db, user, report_id) -> models.PhishReport:
    row = (db.query(models.PhishReport)
           .filter(models.PhishReport.id == report_id, models.PhishReport.tenant_id == user.tenant_id).first())
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return row


@router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return _out(_get(db, user, report_id), full=True)


class StatusIn(BaseModel):
    status: str = Field(pattern="^(new|confirmed|false_positive)$")


@router.patch("/{report_id}")
def set_status(report_id: str, body: StatusIn, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_admin)):
    row = _get(db, user, report_id)
    row.status = body.status
    db.commit()
    audit.log_request(db, request, "phish.status", user, {"id": row.id, "status": body.status})
    return _out(row)


@router.post("/takedown")
def takedown(body: TakedownIn, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_admin)):
    """An abuse report draft for the domain's registrar and hosting network.
    PhishLens doesn't send it: you review it and send it from your own mail."""
    rate_limit(request, f"takedown:{user.tenant_id}", 60)
    domain = normalize_domain(body.domain)
    evidence = _evidence(db, user.tenant_id, domain, _get(db, user, body.report_id) if body.report_id else None)
    draft = phish_reports.takedown(domain, body.url, evidence or ["Impersonates our brand"], user.tenant.name)
    audit.log_request(db, request, "phish.takedown_draft", user, {"domain": domain})
    return draft
