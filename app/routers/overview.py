"""Portfolio overview for MSPs and teams with many domains: clients,
lowest-scoring domains, most frequent alerts, and what changed this month."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..deps import get_current_user
from ..scanner.scoring import grade_for

router = APIRouter(prefix="/api/overview", tags=["overview"])
NO_CLIENT = None  # monitors without a client label


@router.get("")
def overview(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    since = now - timedelta(days=30)
    monitors = db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id).all()
    by_id = {m.id: m for m in monitors}
    alerts = (db.query(models.Alert.kind, models.Alert.monitor_id)
              .filter(models.Alert.tenant_id == user.tenant_id, models.Alert.created_at >= since).all())
    alerts_by_monitor = Counter(mid for _, mid in alerts)
    changes = (db.query(models.DnsChange.monitor_id)
               .filter(models.DnsChange.tenant_id == user.tenant_id, models.DnsChange.created_at >= since).all())
    removed = (db.query(models.AuditEvent)
               .filter(models.AuditEvent.tenant_id == user.tenant_id, models.AuditEvent.action == "monitor.delete",
                       models.AuditEvent.created_at >= month_start).count())

    def row(m):
        return {"id": m.id, "domain": m.domain, "client": m.client, "score": m.last_score,
                "grade": grade_for(m.last_score) if m.last_score is not None else None,
                "active": m.is_active, "alerts_30d": alerts_by_monitor.get(m.id, 0)}

    clients = defaultdict(list)
    for m in monitors:
        clients[m.client or NO_CLIENT].append(m)
    client_rows = []
    for name, ms in clients.items():
        scored = [m for m in ms if m.last_score is not None]
        lowest = min(scored, key=lambda m: m.last_score) if scored else None
        client_rows.append({
            "client": name, "domains": len(ms),
            "avg_score": round(sum(m.last_score for m in scored) / len(scored)) if scored else None,
            "below_70": sum(1 for m in scored if m.last_score < 70),
            "alerts_30d": sum(alerts_by_monitor.get(m.id, 0) for m in ms),
            "lowest": row(lowest) if lowest else None,
        })
    client_rows.sort(key=lambda c: (c["avg_score"] is None, c["avg_score"] or 0))
    scored = [m for m in monitors if m.last_score is not None and m.is_active]
    return {
        "totals": {
            "domains": len(monitors), "active": sum(1 for m in monitors if m.is_active),
            "paused": sum(1 for m in monitors if not m.is_active),
            "clients": sum(1 for c in clients if c is not NO_CLIENT),
            "avg_score": round(sum(m.last_score for m in scored) / len(scored)) if scored else None,
            "added_this_month": sum(1 for m in monitors if m.created_at >= month_start),
            "removed_this_month": removed,
            "alerts_30d": len(alerts), "dns_changes_30d": len(changes),
        },
        "clients": client_rows,
        "lowest": [row(m) for m in sorted(scored, key=lambda m: m.last_score)[:5]],
        "alert_kinds": [{"kind": k, "count": n} for k, n in Counter(k for k, _ in alerts).most_common()],
        "noisiest": [{**row(by_id[mid]), "alerts_30d": n} for mid, n in alerts_by_monitor.most_common(5) if mid in by_id],
    }
