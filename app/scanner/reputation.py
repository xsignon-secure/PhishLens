"""Domain reputation from VirusTotal (optional; off unless VIRUSTOTAL_API_KEY is set).

Informational only: the verdict is shown as a badge on the report and is
never part of the 0-100 score, so scans stay deterministic.

Licensing: VirusTotal's free public API is for non-commercial use only. A
paid (premium) key is required before shipping this in the product.

The free tier also allows 4 lookups/minute and 500/day, so results are
cached per domain and the lookup is skipped (badge omitted) when the local
budget is spent. A failed lookup never breaks a scan.
"""
import logging
import threading
import time
from collections import deque

import httpx

from ..config import settings

log = logging.getLogger("phishlens.reputation")

VT_API = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_GUI = "https://www.virustotal.com/gui/domain/{domain}"
TIMEOUT = 8.0

_cache: dict[str, tuple[float, dict]] = {}
_calls: deque = deque()
_lock = threading.Lock()


def is_configured() -> bool:
    return bool(settings.VIRUSTOTAL_API_KEY)


def _take_budget(now: float) -> bool:
    """Client-side limiter matching the configured per-minute quota."""
    with _lock:
        while _calls and _calls[0] < now - 60:
            _calls.popleft()
        if len(_calls) >= settings.VIRUSTOTAL_RATE_PER_MIN:
            return False
        _calls.append(now)
        return True


def lookup(domain: str) -> dict | None:
    """Return a reputation summary for `domain`, or None if unavailable."""
    if not is_configured():
        return None
    now = time.time()
    with _lock:
        hit = _cache.get(domain)
        if hit and now - hit[0] < settings.VIRUSTOTAL_CACHE_HOURS * 3600:
            return hit[1]
    if not _take_budget(now):
        log.info("virustotal: local rate budget spent, skipping %s", domain)
        return None
    try:
        r = httpx.get(VT_API.format(domain=domain), timeout=TIMEOUT,
                      headers={"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"})
    except Exception as exc:
        log.warning("virustotal lookup for %s failed: %s", domain, type(exc).__name__)
        return None
    if r.status_code == 404:
        summary = {"source": "VirusTotal", "known": False, "malicious": 0, "suspicious": 0,
                   "total": 0, "url": VT_GUI.format(domain=domain)}
    elif r.status_code != 200:
        log.warning("virustotal lookup for %s returned HTTP %s", domain, r.status_code)
        return None
    else:
        try:
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats") or {}
        except Exception:
            return None
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        summary = {
            "source": "VirusTotal", "known": True,
            "malicious": malicious, "suspicious": suspicious, "total": total,
            "analysed_at": attrs.get("last_analysis_date"),
            "url": VT_GUI.format(domain=domain),
        }
    summary["verdict"] = ("malicious" if summary["malicious"] else
                          "suspicious" if summary["suspicious"] else "clean")
    with _lock:
        _cache[domain] = (now, summary)
    return summary
