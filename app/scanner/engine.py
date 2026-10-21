"""Scan orchestration: validate -> guard -> run checks -> score -> persist."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .. import deps, models
from . import recommendations, reputation, scoring

HISTORY_POINTS = 12
TREND_WINDOW_DAYS = 30


def run_scan(db: Session, domain: str, tenant_id: str | None = None) -> models.Scan:
    domain = deps.normalize_domain(domain)
    deps.assert_public_target(domain)
    # Reputation is an informational side lookup: run it alongside the checks.
    with ThreadPoolExecutor(max_workers=1) as pool:
        rep_future = pool.submit(reputation.lookup, domain)
        results = scoring.run_all_checks(domain)
        try:
            rep = rep_future.result()
        except Exception:
            rep = None
    score, grade = scoring.score_results(results)
    result = {
        "domain": domain,
        "score": score,
        "grade": grade,
        "checks": results,
        "action_plan": scoring.action_plan(results),
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "reputation": rep,
    }
    # Attach BEFORE persisting: SQLAlchemy does not track in-place mutations
    # of JSON columns, so mutating after commit would be silently lost.
    recommendations.attach(result)
    scan = models.Scan(
        tenant_id=tenant_id,
        domain=domain,
        score=score,
        grade=grade,
        result=result,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def scan_to_dict(scan: models.Scan, db: Session | None = None) -> dict:
    out = {
        "id": scan.id,
        "domain": scan.domain,
        "score": scan.score,
        "grade": scan.grade,
        "result": scan.result,
        "is_public": scan.is_public,
        "created_at": scan.created_at.isoformat() + "Z",
    }
    if db is not None and scan.tenant_id:
        out["history"] = score_history(db, scan.tenant_id, scan.domain, until=scan.created_at)
    return out


def score_history(db: Session, tenant_id: str, domain: str,
                  until: datetime | None = None) -> dict:
    """A tenant's score trend for one domain, up to (and including) `until`.

    `points` are the most recent scans, oldest first, for a sparkline. The
    trend compares the latest score with the newest scan at least
    TREND_WINDOW_DAYS old ("since last month"); when there is none yet, with
    the oldest scan on record."""
    q = (db.query(models.Scan.score, models.Scan.grade, models.Scan.created_at)
         .filter(models.Scan.tenant_id == tenant_id, models.Scan.domain == domain))
    if until is not None:
        q = q.filter(models.Scan.created_at <= until)
    recent = q.order_by(models.Scan.created_at.desc()).limit(HISTORY_POINTS).all()
    points = [{"score": s, "grade": g, "at": at.isoformat() + "Z"} for s, g, at in reversed(recent)]
    trend = None
    if len(recent) >= 2:
        latest = recent[0]
        cutoff = latest.created_at - timedelta(days=TREND_WINDOW_DAYS)
        baseline = (q.filter(models.Scan.created_at <= cutoff)
                    .order_by(models.Scan.created_at.desc()).first())
        if baseline is None:
            baseline = q.order_by(models.Scan.created_at.asc()).first()
        trend = {
            "from_score": baseline.score, "to_score": latest.score,
            "delta": latest.score - baseline.score,
            "since": baseline.created_at.isoformat() + "Z",
        }
    return {"points": points, "trend": trend}


def check_monitor_lookalikes(monitor: models.Monitor) -> list[models.Alert]:
    """Look for registered lookalikes of a monitored domain. The first check
    records a baseline; later checks alert on newly registered ones."""
    from . import lookalike

    result = lookalike.scan(monitor.domain)
    found = {r["domain"]: r for r in result["registered"]}
    first_check = monitor.lookalikes is None
    previous = set(monitor.lookalikes or [])
    monitor.lookalikes = sorted(found)
    monitor.lookalikes_checked_at = datetime.utcnow()
    new = [found[d] for d in sorted(set(found) - previous)]
    if first_check or not new:
        return []
    listed = ", ".join(f"{r['domain']} ({'accepts mail' if r['mx'] else 'web only'})"
                       for r in new[:10])
    more = f" and {len(new) - 10} more" if len(new) > 10 else ""
    return [models.Alert(
        tenant_id=monitor.tenant_id, monitor_id=monitor.id, kind="lookalike_registered",
        message=f"{monitor.domain}: newly registered lookalike domain(s): {listed}{more}.",
    )]


def rescan_monitor(db: Session, monitor: models.Monitor, check_lookalikes: bool = False) -> dict:
    """Re-scan a monitored domain, record drift alerts, email owners.

    Shared by the API endpoint and the scheduled worker so both behave
    identically. Email is best-effort: alert rows are the source of truth.
    """
    from .. import mailer

    prev_score = monitor.last_score
    # Checks that were already failing at the previous scan are not news: the
    # monitor alerts on drift, so only newly failing checks raise check_failed.
    prev_scan = (
        db.query(models.Scan)
        .filter(models.Scan.tenant_id == monitor.tenant_id, models.Scan.domain == monitor.domain)
        .order_by(models.Scan.created_at.desc())
        .first()
    )
    prev_failed = (
        {c.get("title") for c in (prev_scan.result or {}).get("checks", []) if c.get("status") == "fail"}
        if prev_scan else set()
    )
    scan = run_scan(db, monitor.domain, tenant_id=monitor.tenant_id)
    alerts: list[models.Alert] = []
    # A scan where some checks could not run (DNS timeouts) is not comparable
    # to the baseline: record it, but don't alert on it or move the baseline.
    incomplete = any(c.get("errored") for c in scan.result.get("checks", []))
    if incomplete:
        monitor.last_checked_at = datetime.utcnow()
        db.commit()
        return {"scan": scan, "alerts": [], "emailed": False, "webhook": False}
    if prev_score is not None and scan.score < prev_score and monitor.alert_on_drop:
        alerts.append(models.Alert(
            tenant_id=monitor.tenant_id, monitor_id=monitor.id, kind="score_drop",
            message=f"{monitor.domain}: score dropped {prev_score} -> {scan.score}.",
        ))
    failed = [c["title"] for c in scan.result["checks"]
              if c["status"] == "fail" and c["title"] not in prev_failed]
    if failed and monitor.alert_on_drop:
        alerts.append(models.Alert(
            tenant_id=monitor.tenant_id, monitor_id=monitor.id, kind="check_failed",
            message=f"{monitor.domain}: newly failing checks: {', '.join(failed)}.",
        ))
    if check_lookalikes:
        try:
            alerts.extend(check_monitor_lookalikes(monitor))
        except Exception:
            pass  # informational: a DNS hiccup must not fail the rescan
    for alert in alerts:
        db.add(alert)
    monitor.last_score = scan.score
    monitor.last_checked_at = datetime.utcnow()
    db.commit()
    emailed = webhook_ok = False
    if alerts:
        from .. import webhooks
        # Notifications are best-effort: a delivery error must never undo the
        # committed scan/alert rows or fail the caller.
        try:
            emailed = mailer.notify_monitor_alerts(db, monitor, scan, alerts, prev_score)
        except Exception:
            emailed = False
        try:
            webhook_ok = webhooks.notify_alerts(db, monitor, scan, alerts)
        except Exception:
            webhook_ok = False
    return {"scan": scan, "alerts": alerts, "emailed": emailed, "webhook": webhook_ok}
