"""Built-in rescan scheduler, so monitoring works without a paid cron service.

Enabled with RESCAN_INTERVAL_HOURS (0 = off). Runs in a daemon thread in the
web process; monitors checked recently are skipped, so a restart or a second
worker doesn't rescan everything twice.
"""
import logging
import threading

from .config import settings

log = logging.getLogger("phishlens.scheduler")
_stop = threading.Event()


def _loop(interval_hours: float) -> None:
    from scripts import rescan

    # Wait a little first so startup (migrations, health checks) isn't slowed.
    if _stop.wait(60):
        return
    while True:
        try:
            stats = rescan.run(min_age_hours=max(interval_hours - 1, 1))
            log.info("scheduled rescan %s", stats)
        except Exception:
            log.exception("scheduled rescan failed")
        if _stop.wait(interval_hours * 3600):
            return


def start() -> threading.Thread | None:
    hours = settings.RESCAN_INTERVAL_HOURS
    if hours <= 0:
        return None
    _stop.clear()
    t = threading.Thread(target=_loop, args=(hours,), name="phishlens-rescan", daemon=True)
    t.start()
    log.info("built-in rescans every %s hours", hours)
    return t


def stop() -> None:
    _stop.set()
