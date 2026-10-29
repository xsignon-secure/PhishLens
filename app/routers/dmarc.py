"""DMARC aggregate reports: upload / API ingest, per-sender summary."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, dmarc_reports, forensic, ip_enrich, models, plans
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
    known = {d for (d,) in db.query(models.DmarcReport.domain)
             .filter(models.DmarcReport.tenant_id == tenant_id).distinct()}
    if parsed["domain"] not in known:
        tenant = db.get(models.Tenant, tenant_id)
        limit = plans.plan(tenant)["dmarc_domains"]
        if limit is not None and len(known) >= limit:
            raise dmarc_reports.ReportError(
                f"Your {plans.plan(tenant)['label']} plan includes DMARC reports for {limit} domain"
                f"{'s' if limit != 1 else ''}. Ask the administrator of this service to upgrade your company.")
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
    q = q.filter(models.DmarcReport.date_begin >= plans.since(user.tenant, "dmarc_days"))
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
def domain_summary(domain: str, days: int = 30, enrich: bool = True, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    days = plans.days_cap(user.tenant, "dmarc_days", max(1, min(days, 365)))
    domain = normalize_domain(domain)
    since = datetime.utcnow() - timedelta(days=days)
    reports = (db.query(models.DmarcReport)
               .filter(models.DmarcReport.tenant_id == user.tenant_id,
                       models.DmarcReport.domain == domain,
                       models.DmarcReport.date_begin >= since)
               .order_by(models.DmarcReport.date_begin.desc()).all())
    summary = dmarc_reports.summarize(reports, domain, days)
    return ip_enrich.enrich_summary(summary) if enrich else summary


@router.get("/dkim/{domain}")
def dkim_selector_health(domain: str, days: int = 180, db: Session = Depends(get_db),
                         user: models.User = Depends(get_current_user)):
    """DKIM key health from aggregate reports: each selector that signs for
    the domain, its service, volume, pass rate, last use and key length."""
    from concurrent.futures import ThreadPoolExecutor

    from ..scanner import dns_checks

    days = plans.days_cap(user.tenant, "dmarc_days", max(1, min(days, 730)))
    domain = normalize_domain(domain)
    reports = (db.query(models.DmarcReport)
               .filter(models.DmarcReport.tenant_id == user.tenant_id,
                       models.DmarcReport.domain == domain,
                       models.DmarcReport.date_begin >= datetime.utcnow() - timedelta(days=days))
               .all())
    rows = dmarc_reports.dkim_selectors(reports, domain)[:25]
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda r: dns_checks.dkim_key_info(r["selector"], r["domain"]), rows))
    selectors = [dmarc_reports.dkim_health(r, k) for r, k in zip(rows, keys)]
    return {"domain": domain, "days": days, "selectors": selectors}


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


# ------------------------------------------------------------------ forensic (RUF)
@router.post("/forensic", status_code=201)
async def upload_forensic(request: Request, db: Session = Depends(get_db),
                          user: models.User = Depends(get_current_user)):
    """Send one failure report (.eml, as received) as the request body."""
    plans.require(user.tenant, "ruf")
    rate_limit(request, f"dmarc-upload:{user.tenant_id}", 500)
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > forensic.MAX_BYTES:
        raise HTTPException(status_code=413, detail="File is too large (5 MB max)")
    blob = await request.body()
    try:
        row, created = forensic.store(db, user.tenant_id, forensic.parse(blob))
    except forensic.ForensicError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": row.id, "domain": row.domain, "duplicate": not created}


@router.get("/forensic")
def list_forensic(domain: str | None = None, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    q = db.query(models.ForensicReport).filter(models.ForensicReport.tenant_id == user.tenant_id)
    if domain:
        q = q.filter(models.ForensicReport.domain == normalize_domain(domain))
    rows = q.order_by(models.ForensicReport.created_at.desc()).limit(100).all()
    return [{"id": r.id, "domain": r.domain, "reporter": r.reporter, "source_ip": r.source_ip,
             "arrival_date": r.arrival_date.isoformat() + "Z" if r.arrival_date else None,
             "auth_failure": r.auth_failure, "delivery_result": r.delivery_result,
             "header_from": r.header_from, "original_mail_from": r.original_mail_from,
             "subject": r.subject, "encrypted": bool(r.encrypted)} for r in rows]


@router.get("/forensic/{report_id}.asc")
def forensic_encrypted(report_id: str, db: Session = Depends(get_db),
                       user: models.User = Depends(get_current_user)):
    """The PGP-encrypted details of one failure report, to decrypt with the team's private key."""
    r = (db.query(models.ForensicReport)
         .filter(models.ForensicReport.id == report_id, models.ForensicReport.tenant_id == user.tenant_id).first())
    if not r or not r.encrypted:
        raise HTTPException(status_code=404, detail="Not found")
    return Response(r.encrypted, media_type="application/pgp-encrypted",
                    headers={"Content-Disposition": f'attachment; filename="failure-report-{r.id}.asc"'})
