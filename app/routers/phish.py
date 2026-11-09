"""Phishing report inbox and takedown request drafts."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, models, phish_reports
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, require_admin

router = APIRouter(prefix="/api/phish-reports", tags=["phishing reports"])


def _out(r: models.PhishReport, full: bool = False) -> dict:
    out = {"id": r.id, "subject": r.subject, "sender": r.sender, "verdict": r.verdict, "score": r.score,
           "status": r.status, "reported_by": r.reported_by, "created_at": r.created_at.isoformat() + "Z",
           "links": [{"url": x.get("url"), "domain": x.get("domain"), "verdict": x.get("verdict")}
                     for x in r.links or []]}
    if full:
        out["header"] = r.header
        out["links"] = r.links or []
    return out


@router.post("", status_code=201)
async def report(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Send the suspicious email as the request body (raw .eml, or a message
    that has it attached). Anyone in the company can report."""
    rate_limit(request, f"phish-report:{user.tenant_id}", 300)
    blob = await request.body()
    try:
        parsed = phish_reports.parse(blob)
    except phish_reports.ReportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = phish_reports.triage(parsed)
    row = models.PhishReport(tenant_id=user.tenant_id, reported_by=user.email, subject=parsed["subject"],
                             sender=parsed["from"], verdict=result["verdict"], score=result["score"],
                             header=result["header"], links=result["links"])
    db.add(row)
    db.commit()
    audit.log_request(db, request, "phish.report", user, {"verdict": row.verdict})
    return _out(row, full=True)


@router.get("")
def list_reports(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (db.query(models.PhishReport).filter(models.PhishReport.tenant_id == user.tenant_id)
            .order_by(models.PhishReport.created_at.desc()).limit(200).all())
    return [_out(r) for r in rows]


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


class TakedownIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    url: str | None = Field(default=None, max_length=2000)
    report_id: str | None = None


@router.post("/takedown")
def takedown(body: TakedownIn, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_admin)):
    """An abuse report draft for the domain's registrar and hosting network.
    PhishLens doesn't send it: you review it and send it from your own mail."""
    rate_limit(request, f"takedown:{user.tenant_id}", 60)
    domain = normalize_domain(body.domain)
    evidence = []
    if body.report_id:
        r = _get(db, user, body.report_id)
        evidence.append(f"Reported by an employee on {r.created_at:%Y-%m-%d}: subject \"{r.subject}\" from {r.sender}")
        for link in r.links or []:
            if link.get("domain") == domain or (link.get("url") and domain in link["url"]):
                evidence += [s["text"] for s in link.get("signals") or []][:5]
                evidence += [f"Listed by {f['source']}" for f in link.get("feeds") or [] if f.get("listed")]
        evidence += [f["text"] for f in (r.header or {}).get("findings") or [] if f.get("level") == "fail"][:3]
    for m in db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id).all():
        if domain in (m.lookalikes or []):
            evidence.append(f"Lookalike of our domain {m.domain}, found by PhishLens monitoring")
    draft = phish_reports.takedown(domain, body.url, evidence or ["Impersonates our brand"], user.tenant.name)
    audit.log_request(db, request, "phish.takedown_draft", user, {"domain": domain})
    return draft
