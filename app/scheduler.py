"""Built-in rescan scheduler, so monitoring works without a paid cron service.

Enabled with RESCAN_INTERVAL_HOURS (0 = off). Runs in a daemon thread in the
web process. A database lease makes sure only one worker or instance runs a
round, and monitors checked recently are skipped, so restarts don't rescan
everything twice.
"""
import logging
import os
import socket
import threading
from datetime import datetime, timedelta

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from .config import settings

log = logging.getLogger("phishlens.scheduler")
_stop = threading.Event()
HOLDER = f"{socket.gethostname()}:{os.getpid()}"[:64]


def acquire_lease(name: str, seconds: int, holder: str = HOLDER) -> bool:
    """Take (or renew) the named lease if it is free or expired. Atomic: the
    conditional UPDATE / INSERT lets only one contender win."""
    from . import models
    from .database import SessionLocal

    db = SessionLocal()
    now = datetime.utcnow()
    try:
        won = db.execute(
            update(models.JobLease)
            .where(models.JobLease.name == name,
                   (models.JobLease.expires_at < now) | (models.JobLease.holder == holder))
            .values(holder=holder, expires_at=now + timedelta(seconds=seconds))
        ).rowcount
        if not won:
            db.add(models.JobLease(name=name, holder=holder, expires_at=now + timedelta(seconds=seconds)))
            try:
                db.flush()
                won = 1
            except IntegrityError:  # someone else holds it
                db.rollback()
                return False
        db.commit()
        return bool(won)
    finally:
        db.close()


def _loop(interval_hours: float) -> None:
    from scripts import rescan

    # Wait a little first so startup (migrations, health checks) isn't slowed.
    if _stop.wait(60):
        return
    while True:
        try:
            if acquire_lease("rescan", int(interval_hours * 3600) - 60):
                stats = rescan.run(min_age_hours=max(interval_hours - 1, 1))
                log.info("scheduled rescan %s", stats)
            else:
                log.info("scheduled rescan skipped: another worker holds the lease")
        except Exception:
            log.exception("scheduled rescan failed")
        if _stop.wait(interval_hours * 3600):
            return


def _fetch_loop(minutes: float) -> None:
    from scripts import fetch_dmarc_reports

    if _stop.wait(90):
        return
    while True:
        try:
            if acquire_lease("report-fetch", int(minutes * 60) - 30):
                stats = fetch_dmarc_reports.run()
                if stats:
                    log.info("report fetch %s", stats)
        except Exception:
            log.exception("report fetch failed")
        if _stop.wait(minutes * 60):
            return


def start() -> threading.Thread | None:
    """Start the background jobs that are switched on. Returns the rescan
    thread (or None when rescans are off)."""
    _stop.clear()
    minutes = settings.REPORT_FETCH_MINUTES
    if minutes > 0:
        threading.Thread(target=_fetch_loop, args=(minutes,), name="phishlens-reports", daemon=True).start()
        log.info("built-in report fetching every %s minutes", minutes)
    hours = settings.RESCAN_INTERVAL_HOURS
    if hours <= 0:
        return None
    t = threading.Thread(target=_loop, args=(hours,), name="phishlens-rescan", daemon=True)
    t.start()
    log.info("built-in rescans every %s hours", hours)
    return t


def stop() -> None:
    _stop.set()
