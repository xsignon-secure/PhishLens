"""Monitors: watch domains for score drift; rescan endpoint for scheduled jobs."""
from datetime import datetime

import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, models, plans, schemas
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, tenant_alerts, tenant_monitors
from ..scanner import engine

router = APIRouter(prefix="/api/monitors", tags=["monitors"])


@router.get("")
def list_monitors(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    monitors = tenant_monitors(db, user).order_by(models.Monitor.created_at.desc()).all()
    return [
        {
            "id": m.id, "domain": m.domain, "last_score": m.last_score,
            "last_checked_at": m.last_checked_at.isoformat() + "Z" if m.last_checked_at else None,
            "is_active": m.is_active, "client": m.client, "alert_level": m.alert_level or "balanced",
            "lookalikes": len(m.lookalikes or []),
            "impersonating": sum(1 for v in (m.lookalike_visual or {}).values() if v.get("verdict") == "impersonating"),
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
    limit = settings.MAX_MONITORS_PER_TEAM  # 0 = unlimited; a server operator's abuse brake
    if limit and tenant_monitors(db, user).filter(models.Monitor.is_active.is_(True)).count() >= limit:
        raise HTTPException(status_code=429, detail=f"This server allows {limit} monitored domains per team")
    plans.check_limit(user.tenant, "monitors",
                      tenant_monitors(db, user).filter(models.Monitor.is_active.is_(True)).count(), "monitored domains")
    # Baseline scan BEFORE inserting: run_scan refuses unscannable domains, and
    # a failure must not leave a broken monitor behind.
    scan = engine.run_scan(db, domain, tenant_id=user.tenant_id)
    monitor = models.Monitor(tenant_id=user.tenant_id, domain=domain,
                             client=(payload.client or "").strip() or None,
                             alert_level=payload.alert_level,
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


BULK_MAX = 200


def _bulk_baseline(tenant_id: str, monitor_ids: list[str]) -> None:
    """Baseline scans for monitors added in bulk, one after another in the
    background. A domain that can't be scanned (not public, doesn't exist)
    is removed again."""
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        for mid in monitor_ids:
            m = db.query(models.Monitor).filter(models.Monitor.id == mid,
                                                models.Monitor.tenant_id == tenant_id).first()
            if not m:
                continue
            try:
                scan = engine.run_scan(db, m.domain, tenant_id=tenant_id)
            except HTTPException:
                db.delete(m)
                db.commit()
                continue
            except Exception:
                db.rollback()
                continue
            m.last_score, m.last_checked_at = scan.score, datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("/bulk", status_code=202)
def add_monitors_bulk(payload: schemas.MonitorBulkIn, request: Request, background: BackgroundTasks,
                      db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Monitor a whole portfolio at once (paste a list or a registrar export).
    Monitors are created now; their first scans run in the background."""
    rate_limit(request, f"monitor-bulk:{user.tenant_id}", 10)
    wanted, skipped = [], []
    for raw in re.split(r"[\s,;]+", payload.domains):
        if not raw:
            continue
        try:
            d = normalize_domain(raw)
        except HTTPException:
            skipped.append({"domain": raw[:253], "reason": "not a valid domain"})
            continue
        if d not in wanted:
            wanted.append(d)
    if len(wanted) > BULK_MAX:
        raise HTTPException(status_code=400, detail=f"Add at most {BULK_MAX} domains at a time")
    existing = {d for (d,) in db.query(models.Monitor.domain).filter(models.Monitor.tenant_id == user.tenant_id)}
    active = tenant_monitors(db, user).filter(models.Monitor.is_active.is_(True)).count()
    room = []
    caps = [c for c in (settings.MAX_MONITORS_PER_TEAM, plans.plan(user.tenant)["monitors"]) if c]
    cap = min(caps) if caps else None
    for d in wanted:
        if d in existing:
            skipped.append({"domain": d, "reason": "already monitored"})
        elif cap is not None and active + len(room) >= cap:
            skipped.append({"domain": d, "reason": f"over the limit of {cap} monitored domains"})
        else:
            room.append(d)
    client = (payload.client or "").strip() or None
    rows = [models.Monitor(tenant_id=user.tenant_id, domain=d, client=client, alert_level=payload.alert_level)
            for d in room]
    db.add_all(rows)
    db.commit()
    background.add_task(_bulk_baseline, user.tenant_id, [m.id for m in rows])
    audit.log_request(db, request, "monitor.bulk_create", user, {"count": len(rows), "skipped": len(skipped)})
    return {"added": room, "skipped": skipped}


@router.patch("/{monitor_id}")
def update_monitor(monitor_id: str, payload: schemas.MonitorUpdateIn, request: Request,
                   db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    monitor = tenant_monitors(db, user).filter(models.Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    fields = payload.model_fields_set
    if "client" in fields or not fields:
        monitor.client = (payload.client or "").strip() or None
    if payload.alert_level is not None:
        monitor.alert_level = payload.alert_level
    db.commit()
    audit.log_request(db, request, "monitor.update", user,
                      {"domain": monitor.domain, "client": monitor.client, "alert_level": monitor.alert_level})
    return {"id": monitor.id, "client": monitor.client, "alert_level": monitor.alert_level}


@router.get("/{monitor_id}/changes")
def dns_changes(monitor_id: str, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    """The DNS timeline: every email-security record change seen by rescans."""
    monitor = tenant_monitors(db, user).filter(models.Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    rows = (db.query(models.DnsChange)
            .filter(models.DnsChange.tenant_id == user.tenant_id,
                    models.DnsChange.monitor_id == monitor.id)
            .order_by(models.DnsChange.created_at.desc()).limit(200).all())
    return {"domain": monitor.domain, "changes": [
        {"record": c.record, "old": c.old, "new": c.new, "at": c.created_at.isoformat() + "Z"}
        for c in rows]}


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
    (db.query(models.DnsChange)
     .filter(models.DnsChange.tenant_id == user.tenant_id, models.DnsChange.monitor_id == monitor.id)
     .delete(synchronize_session=False))
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
