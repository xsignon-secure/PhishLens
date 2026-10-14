"""Monitors: watch domains for score drift; rescan endpoint for scheduled jobs."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, models, schemas
from ..database import get_db
from ..deps import get_current_user, normalize_domain, tenant_alerts, tenant_monitors
from ..scanner import engine

router = APIRouter(prefix="/api/monitors", tags=["monitors"])

FREE_MONITOR_LIMIT = 3


@router.get("")
def list_monitors(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    monitors = tenant_monitors(db, user).order_by(models.Monitor.created_at.desc()).all()
    return [
        {
            "id": m.id, "domain": m.domain, "last_score": m.last_score,
            "last_checked_at": m.last_checked_at.isoformat() + "Z" if m.last_checked_at else None,
            "is_active": m.is_active,
            "history": engine.score_history(db, user.tenant_id, m.domain),
        }
        for m in monitors
    ]


@router.post("", status_code=201)
def add_monitor(payload: schemas.MonitorIn, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    domain = normalize_domain(payload.domain)
    existing = tenant_monitors(db, user).filter(models.Monitor.domain == domain).first()
    if existing:
        raise HTTPException(status_code=409, detail="Domain already monitored")
    count = tenant_monitors(db, user).filter(models.Monitor.is_active.is_(True)).count()
    if user.tenant.plan == "free" and count >= FREE_MONITOR_LIMIT:
        raise HTTPException(status_code=402, detail=f"Free plan allows {FREE_MONITOR_LIMIT} monitors")
    # Baseline scan BEFORE inserting: run_scan refuses unscannable domains, and
    # a failure must not leave a monitor behind that counts against the limit.
    scan = engine.run_scan(db, domain, tenant_id=user.tenant_id)
    monitor = models.Monitor(tenant_id=user.tenant_id, domain=domain,
                             last_score=scan.score, last_checked_at=datetime.utcnow())
    db.add(monitor)
    try:
        db.commit()
    except IntegrityError:  # concurrent add of the same domain
        db.rollback()
        raise HTTPException(status_code=409, detail="Domain already monitored")
    db.refresh(monitor)
    audit.log_request(db, request, "monitor.create", user, {"domain": domain, "score": scan.score})
    return {"id": monitor.id, "domain": monitor.domain, "last_score": monitor.last_score}


@router.delete("/{monitor_id}")
def remove_monitor(monitor_id: str, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    monitor = tenant_monitors(db, user).filter(models.Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    domain = monitor.domain
    # Alerts reference the monitor by foreign key; Postgres rejects deleting a
    # monitor that still has alert rows (SQLite only allowed it because it
    # doesn't enforce foreign keys by default).
    tenant_alerts(db, user).filter(models.Alert.monitor_id == monitor.id).delete(synchronize_session=False)
    db.delete(monitor)
    db.commit()
    audit.log_request(db, request, "monitor.delete", user, {"domain": domain})
    return {"ok": True}


@router.post("/{monitor_id}/rescan")
def rescan_monitor(monitor_id: str, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    """Re-scan one monitored domain now; records an alert on score drops."""
    monitor = tenant_monitors(db, user).filter(models.Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    result = engine.rescan_monitor(db, monitor)
    scan = result["scan"]
    audit.log_request(db, request, "monitor.rescan", user,
                      {"domain": monitor.domain, "score": scan.score,
                       "alerts": len(result["alerts"])})
    return {"score": scan.score, "grade": scan.grade,
            "alerted": bool(result["alerts"]), "emailed": result["emailed"]}


@router.get("/alerts/list")
def list_alerts(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    alerts = tenant_alerts(db, user).order_by(models.Alert.created_at.desc()).limit(50).all()
    return [
        {"id": a.id, "kind": a.kind, "message": a.message,
         "created_at": a.created_at.isoformat() + "Z"}
        for a in alerts
    ]
