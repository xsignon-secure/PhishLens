"""Client portal: an MSP's customer signs in and sees their own domains,
read-only. A "client" login is tied to one client label (Monitor.client) in
the MSP's company; every query here filters on it, and deps.get_current_user
refuses client logins on every other API."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, branding, models, summary
from ..database import get_db
from ..deps import get_current_user, rate_limit
from ..scanner import engine
from ..scanner.scoring import grade_for
from .scans import _pdf_response

router = APIRouter(prefix="/api/portal", tags=["client portal"])


def require_client(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "client" or not user.client_scope:
        raise HTTPException(status_code=403, detail="Client portal accounts only")
    return user


def _monitors(db: Session, user: models.User):
    return (db.query(models.Monitor)
            .filter(models.Monitor.tenant_id == user.tenant_id, models.Monitor.client == user.client_scope))


def _domains(db: Session, user: models.User) -> set[str]:
    return {d for (d,) in _monitors(db, user).with_entities(models.Monitor.domain).all()}


def _latest_scan(db: Session, user: models.User, domain: str) -> models.Scan | None:
    return (db.query(models.Scan)
            .filter(models.Scan.tenant_id == user.tenant_id, models.Scan.domain == domain)
            .order_by(models.Scan.created_at.desc()).first())


def _scan(db: Session, user: models.User, scan_id: str) -> models.Scan:
    scan = (db.query(models.Scan)
            .filter(models.Scan.id == scan_id, models.Scan.tenant_id == user.tenant_id).first())
    if not scan or scan.domain not in _domains(db, user):
        raise HTTPException(status_code=404, detail="Report not found")
    return scan


@router.get("")
def portal_home(db: Session = Depends(get_db), user: models.User = Depends(require_client)):
    tenant = user.tenant
    brand = branding.for_tenant(tenant) or {}
    monitors = _monitors(db, user).order_by(models.Monitor.domain).all()
    since = datetime.utcnow() - timedelta(days=30)
    ids = [m.id for m in monitors]
    alerts = (db.query(models.Alert).filter(models.Alert.tenant_id == user.tenant_id,
                                            models.Alert.monitor_id.in_(ids), models.Alert.created_at >= since)
              .order_by(models.Alert.created_at.desc()).limit(50).all()) if ids else []
    names = {m.id: m.domain for m in monitors}
    domains = []
    for m in monitors:
        scan = _latest_scan(db, user, m.domain)
        domains.append({"domain": m.domain, "score": m.last_score,
                        "grade": grade_for(m.last_score) if m.last_score is not None else None,
                        "last_checked_at": m.last_checked_at.isoformat() + "Z" if m.last_checked_at else None,
                        "scan_id": scan.id if scan else None,
                        "alerts_30d": sum(1 for a in alerts if a.monitor_id == m.id)})
    open_tasks = (db.query(models.RemediationTask)
                  .filter(models.RemediationTask.tenant_id == user.tenant_id,
                          models.RemediationTask.domain.in_(list(names.values())),
                          models.RemediationTask.status == "open").count()) if names else 0
    return {"client": user.client_scope,
            "provider": brand.get("name") or tenant.name,
            "brand_color": brand.get("color"), "logo": brand.get("logo_data_url"),
            "domains": domains, "open_tasks": open_tasks,
            "alerts": [{"domain": names.get(a.monitor_id), "kind": a.kind, "message": a.message,
                        "at": a.created_at.isoformat() + "Z"} for a in alerts[:20]]}


@router.get("/scans/{scan_id}")
def portal_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(require_client)):
    return engine.scan_to_dict(_scan(db, user, scan_id), db)


@router.get("/scans/{scan_id}/summary")
def portal_summary(scan_id: str, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_client)):
    rate_limit(request, f"summary:{user.id}", 60)
    return summary.get(db, _scan(db, user, scan_id))


@router.get("/scans/{scan_id}/pdf")
def portal_pdf(scan_id: str, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_client)):
    scan = _scan(db, user, scan_id)
    audit.log_request(db, request, "portal.pdf", user, {"scan_id": scan.id, "domain": scan.domain})
    return _pdf_response(scan, db, with_history=True)
