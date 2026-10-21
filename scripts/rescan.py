#!/usr/bin/env python3
"""Scheduled monitor rescans. Run weekly from cron:

    0 6 * * 1  cd /srv/phishlens && .venv/bin/python scripts/rescan.py >> /var/log/phishlens-rescan.log 2>&1

Rescans every active monitor, records drift alerts, and emails tenant owners
(if SMTP_* is configured). Skips monitors checked within --min-age-hours
(default 20) unless --force is given.
"""
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import models  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.scanner import engine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Rescan all active PhishLens monitors")
    parser.add_argument("--force", action="store_true", help="rescan even if recently checked")
    parser.add_argument("--min-age-hours", type=float, default=20)
    parser.add_argument("--domain", help="rescan only this domain")
    parser.add_argument("--tenant", help="rescan only this tenant id")
    parser.add_argument("--lookalike-days", type=float, default=6,
                        help="look for new lookalike domains when the last check is older "
                             "than this many days (0 disables)")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        q = db.query(models.Monitor).filter(models.Monitor.is_active.is_(True))
        if args.domain:
            q = q.filter(models.Monitor.domain == args.domain.strip().lower().rstrip("."))
        if args.tenant:
            q = q.filter(models.Monitor.tenant_id == args.tenant)
        monitors = q.all()

        cutoff = datetime.utcnow() - timedelta(hours=args.min_age_hours)
        done, skipped, failed, alerted = 0, 0, 0, 0
        for monitor in monitors:
            if (not args.force and monitor.last_checked_at
                    and monitor.last_checked_at > cutoff):
                skipped += 1
                continue
            try:
                due = args.lookalike_days > 0 and (
                    not monitor.lookalikes_checked_at
                    or monitor.lookalikes_checked_at
                    < datetime.utcnow() - timedelta(days=args.lookalike_days))
                result = engine.rescan_monitor(db, monitor, check_lookalikes=due)
                done += 1
                alerted += len(result["alerts"])
                print(f"[{datetime.utcnow().isoformat()}] {monitor.domain} "
                      f"tenant={monitor.tenant_id[:8]} score={result['scan'].score} "
                      f"alerts={len(result['alerts'])} emailed={result['emailed']}", flush=True)
            except Exception as exc:
                # A failed scan leaves the session mid-transaction; roll back
                # so the remaining monitors can still be processed.
                db.rollback()
                failed += 1
                detail = getattr(exc, "detail", None) or exc
                print(f"[{datetime.utcnow().isoformat()}] {monitor.domain} FAILED: {detail}",
                      flush=True)
        print(f"done={done} skipped={skipped} failed={failed} alerts={alerted}")
        return 1 if failed else 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
