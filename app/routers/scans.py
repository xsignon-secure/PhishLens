"""Scans: public one-off scan (funnel), tenant history, shareable reports."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import audit, models, pdf_report, plans, schemas
from ..config import settings
from ..database import get_db
from ..deps import client_ip, get_current_user, public_scan_limit, rate_limit, tenant_scans
from ..scanner import engine

router = APIRouter(prefix="/api/scans", tags=["scans"])

HISTORY_PAGE = 500


def _pdf_bytes(scan: models.Scan, db: Session, with_history: bool = False) -> tuple[bytes, str]:
    # History is the tenant's private trend: only in the signed-in export.
    data = engine.scan_to_dict(scan, db if with_history else None)
    share_url = f"{settings.APP_URL}/r/{scan.id}" if scan.is_public else None
    from .. import branding
    tenant = (db.query(models.Tenant).filter(models.Tenant.id == scan.tenant_id).first()
              if scan.tenant_id else None)
    pdf = pdf_report.render(data, share_url=share_url, brand=branding.for_tenant(tenant))
    return pdf, f"phishlens-{scan.domain}-{scan.created_at:%Y-%m-%d}.pdf"


def _pdf_response(scan: models.Scan, db: Session, with_history: bool = False) -> Response:
    pdf, filename = _pdf_bytes(scan, db, with_history)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "Cache-Control": "private, no-store"})


@router.get("/public/{scan_id}/pdf")
def public_scan_pdf(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """PDF of an anonymous landing-page scan, reachable only by its unguessable id
    (the same rule as the JSON result the visitor already holds)."""
    rate_limit(request, f"pdf:{client_ip(request)}", 30)
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id,
                                        models.Scan.tenant_id.is_(None)).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _pdf_response(scan, db)


@router.get("/shared/{scan_id}/pdf")
def shared_scan_pdf(scan_id: str, request: Request, db: Session = Depends(get_db)):
    rate_limit(request, f"pdf:{client_ip(request)}", 30)
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.is_public.is_(True)).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    return _pdf_response(scan, db)


@router.get("/history/{domain}")
def domain_history(domain: str, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    """Score trend for one of the tenant's domains."""
    from ..deps import normalize_domain
    return {"domain": normalize_domain(domain),
            **engine.score_history(db, user.tenant_id, normalize_domain(domain))}


@router.post("/public")
def public_scan(payload: schemas.ScanIn, request: Request, db: Session = Depends(get_db)):
    """No-auth scan for the landing page funnel. Rate-limited per IP."""
    public_scan_limit(request)
    scan = engine.run_scan(db, payload.domain, tenant_id=None)
    audit.log_request(db, request, "scan.public", detail={"domain": scan.domain, "score": scan.score})
    return engine.scan_to_dict(scan)


@router.post("", status_code=201)
def create_scan(
    payload: schemas.ScanIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    scan = engine.run_scan(db, payload.domain, tenant_id=user.tenant_id)
    audit.log_request(db, request, "scan.create", user, {"domain": scan.domain, "score": scan.score})
    return engine.scan_to_dict(scan, db)


@router.get("")
def list_scans(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scans = (
        tenant_scans(db, user)
        .order_by(models.Scan.created_at.desc())
        .limit(HISTORY_PAGE)
        .all()
    )
    return [engine.scan_to_dict(s) for s in scans]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scan = (
        tenant_scans(db, user)
        .filter(models.Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return engine.scan_to_dict(scan, db)


@router.get("/{scan_id}/pdf")
def scan_pdf(scan_id: str, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(get_current_user)):
    scan = tenant_scans(db, user).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    audit.log_request(db, request, "report.pdf", user, {"scan_id": scan.id, "domain": scan.domain})
    return _pdf_response(scan, db, with_history=True)


@router.post("/{scan_id}/email")
def email_scan(scan_id: str, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    """Email the PDF report to the signed-in user. Never to an address typed in:
    that would make the app a spam relay."""
    from .. import mailer
    scan = tenant_scans(db, user).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not mailer.config_for(user.tenant):
        raise HTTPException(status_code=503, detail="Email is not set up on this server")
    rate_limit(request, f"report-email:{user.id}", 10)
    pdf, filename = _pdf_bytes(scan, db, with_history=True)
    body = (f"Your PhishLens report for {scan.domain} is attached.\n\n"
            f"Score: {scan.score}/100 (grade {scan.grade}).\n"
            f"Open it online: {settings.APP_URL}/dashboard\n")
    if not mailer.send_email([user.email], f"Report for {scan.domain}", body,
                             attachments=[(filename, pdf, "application/pdf")], tenant=user.tenant):
        raise HTTPException(status_code=502, detail="The email could not be sent")
    audit.log_request(db, request, "report.email", user, {"scan_id": scan.id, "domain": scan.domain})
    return {"ok": True, "to": user.email}


@router.get("/shared/{scan_id}")
def get_shared_scan(scan_id: str, db: Session = Depends(get_db)):
    """Shareable report link. Only scans explicitly marked public."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.is_public.is_(True)).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    return engine.scan_to_dict(scan)


@router.post("/{scan_id}/share")
def share_scan(scan_id: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    plans.require(user.tenant, "share")
    scan = tenant_scans(db, user).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.is_public = True
    db.commit()
    audit.log_request(db, request, "report.share", user, {"scan_id": scan.id, "domain": scan.domain})
    return {"share_url": f"/r/{scan.id}"}


@router.post("/{scan_id}/unshare")
def unshare_scan(scan_id: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scan = tenant_scans(db, user).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.is_public = False
    db.commit()
    audit.log_request(db, request, "report.unshare", user, {"scan_id": scan.id})
    return {"ok": True}
