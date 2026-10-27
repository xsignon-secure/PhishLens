"""SMTP TLS reports (TLS-RPT): upload / API ingest and per-domain summary."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, models, tls_reports
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit

router = APIRouter(prefix="/api/tlsrpt", tags=["tls-rpt"])


@router.post("/reports", status_code=201)
async def upload_report(request: Request, db: Session = Depends(get_db),
                        user: models.User = Depends(get_current_user)):
    """Send one report (.json or .json.gz, as received) as the request body."""
    rate_limit(request, f"dmarc-upload:{user.tenant_id}", 500)
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > tls_reports.MAX_COMPRESSED:
        raise HTTPException(status_code=413, detail="File is too large (5 MB max)")
    blob = await request.body()
    if not blob:
        raise HTTPException(status_code=400, detail="Empty upload")
    try:
        row, created = tls_reports.store(db, user.tenant_id, tls_reports.parse(blob))
    except tls_reports.TlsReportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if created:
        audit.log_request(db, request, "tlsrpt.report.upload", user, {"domain": row.domain, "org": row.org_name})
    return {"id": row.id, "domain": row.domain, "org_name": row.org_name,
            "successful": row.success_count, "failed": row.failure_count, "duplicate": not created}


@router.get("/domains")
def report_domains(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (db.query(models.TlsReport.domain).filter(models.TlsReport.tenant_id == user.tenant_id)
            .distinct().all())
    return sorted(r[0] for r in rows)


@router.get("/summary/{domain}")
def domain_summary(domain: str, days: int = 30, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    days = max(1, min(days, 365))
    domain = normalize_domain(domain)
    reports = (db.query(models.TlsReport)
               .filter(models.TlsReport.tenant_id == user.tenant_id, models.TlsReport.domain == domain,
                       models.TlsReport.date_begin >= tls_reports.default_window(days))
               .order_by(models.TlsReport.date_begin.desc()).all())
    return tls_reports.summarize(reports, domain, days)
