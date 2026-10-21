"""DMARC aggregate reports: upload / API ingest, per-sender summary."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, dmarc_reports, models
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit

router = APIRouter(prefix="/api/dmarc", tags=["dmarc"])


def store_report(db: Session, tenant_id: str, parsed: dict) -> tuple[models.DmarcReport, bool]:
    """Save a parsed report; returns (row, created). Re-sent reports (same
    reporter + report id) are recognised and not counted twice."""
    report_id = parsed["report_id"] or (
        f"{parsed['domain']}-{parsed['date_begin']:%Y%m%d%H%M%S}" if parsed["date_begin"] else "")
    if not report_id:
        raise dmarc_reports.ReportError("Report has no report_id")
    existing = (db.query(models.DmarcReport)
                .filter(models.DmarcReport.tenant_id == tenant_id,
                        models.DmarcReport.org_name == parsed["org_name"],
                        models.DmarcReport.report_id == report_id)
                .first())
    if existing:
        return existing, False
    records = parsed["records"]
    row = models.DmarcReport(
        tenant_id=tenant_id, domain=parsed["domain"], org_name=parsed["org_name"],
        report_id=report_id, date_begin=parsed["date_begin"], date_end=parsed["date_end"],
        policy=parsed["policy"], records=records,
        message_count=sum(r["count"] for r in records),
        pass_count=sum(r["count"] for r in records if r["dkim"] == "pass" or r["spf"] == "pass"),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:  # concurrent upload of the same report
        db.rollback()
        return store_report(db, tenant_id, parsed)
    db.refresh(row)
    return row, True


@router.post("/reports", status_code=201)
async def upload_report(request: Request, db: Session = Depends(get_db),
                        user: models.User = Depends(get_current_user)):
    """Send one report file (raw .xml, .xml.gz or .zip) as the request body."""
    rate_limit(request, f"dmarc-upload:{user.tenant_id}", 500)
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > dmarc_reports.MAX_COMPRESSED:  # refuse before reading it into memory
        raise HTTPException(status_code=413, detail="File is too large (10 MB max)")
    blob = await request.body()
    if not blob:
        raise HTTPException(status_code=400, detail="Empty upload")
    if len(blob) > dmarc_reports.MAX_COMPRESSED:
        raise HTTPException(status_code=413, detail="File is too large (10 MB max)")
    try:
        parsed = dmarc_reports.parse(blob)
        row, created = store_report(db, user.tenant_id, parsed)
    except dmarc_reports.ReportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if created:
        audit.log_request(db, request, "dmarc.report.upload", user,
                          {"domain": row.domain, "org": row.org_name, "messages": row.message_count})
    return {"id": row.id, "domain": row.domain, "org_name": row.org_name,
            "messages": row.message_count, "duplicate": not created}


@router.get("/reports")
def list_reports(domain: str | None = None, db: Session = Depends(get_db),
                 user: models.User = Depends(get_current_user)):
    q = db.query(models.DmarcReport).filter(models.DmarcReport.tenant_id == user.tenant_id)
    if domain:
        q = q.filter(models.DmarcReport.domain == normalize_domain(domain))
    rows = q.order_by(models.DmarcReport.date_begin.desc()).limit(200).all()
    return [{"id": r.id, "domain": r.domain, "org_name": r.org_name,
             "date_begin": r.date_begin.isoformat() + "Z" if r.date_begin else None,
             "date_end": r.date_end.isoformat() + "Z" if r.date_end else None,
             "messages": r.message_count, "passed": r.pass_count} for r in rows]


@router.get("/domains")
def report_domains(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (db.query(models.DmarcReport.domain)
            .filter(models.DmarcReport.tenant_id == user.tenant_id)
            .distinct().all())
    return sorted(r[0] for r in rows)


@router.get("/summary/{domain}")
def domain_summary(domain: str, days: int = 30, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    days = max(1, min(days, 365))
    domain = normalize_domain(domain)
    since = datetime.utcnow() - timedelta(days=days)
    reports = (db.query(models.DmarcReport)
               .filter(models.DmarcReport.tenant_id == user.tenant_id,
                       models.DmarcReport.domain == domain,
                       models.DmarcReport.date_begin >= since)
               .order_by(models.DmarcReport.date_begin.desc()).all())
    return dmarc_reports.summarize(reports, domain, days)


@router.delete("/reports/{report_id}")
def delete_report(report_id: str, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    row = (db.query(models.DmarcReport)
           .filter(models.DmarcReport.tenant_id == user.tenant_id,
                   models.DmarcReport.id == report_id).first())
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete(row)
    db.commit()
    audit.log_request(db, request, "dmarc.report.delete", user, {"domain": row.domain})
    return {"ok": True}
