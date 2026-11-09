"""State of email security: aggregate statistics from recent scans.

Only counts and percentages are published, never a domain name, and a group
(a top-level domain) is shown only when it has at least MIN_GROUP domains, so
no single company can be picked out of the numbers."""
import re
import time
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models

WINDOW_DAYS = 90
MIN_GROUP = 20
MIN_TOTAL = 50
CACHE_SECONDS = 3600
GRADES = ("A", "B", "C", "D", "F")
_cache: dict = {}


def _policy(check: dict) -> str | None:
    m = re.search(r"\bp=(none|quarantine|reject)\b", check.get("record") or check.get("details") or "", re.I)
    return m.group(1).lower() if m else None


def _measures(checks: dict[str, dict]) -> dict[str, bool]:
    def ok(key, allow_warn=False):
        c = checks.get(key)
        return bool(c) and not c.get("errored") and (c["status"] == "pass" or (allow_warn and c["status"] == "warn"))
    dmarc = checks.get("dmarc") or {}
    policy = _policy(dmarc) if dmarc.get("record") else None
    return {
        "spf": ok("spf", allow_warn=True),
        "dmarc": policy is not None,
        "enforced": policy in ("quarantine", "reject"),
        "reject": policy == "reject",
        "dkim": ok("dkim", allow_warn=True),
        "mta_sts": ok("mta-sts"),
        "tls_rpt": ok("tls-rpt"),
        "bimi": ok("bimi"),
        "dnssec": ok("dnssec"),
    }


def _empty() -> dict:
    return {"domains": 0, "score_sum": 0, "grades": dict.fromkeys(GRADES, 0), "counts": {}}


def _add(group: dict, scan, measures: dict) -> None:
    group["domains"] += 1
    group["score_sum"] += scan.score
    group["grades"][scan.grade] = group["grades"].get(scan.grade, 0) + 1
    for k, v in measures.items():
        group["counts"][k] = group["counts"].get(k, 0) + int(v)


def _publish(group: dict) -> dict:
    n = group["domains"]
    return {"domains": n, "avg_score": round(group["score_sum"] / n) if n else 0,
            "grades": {g: round(100 * c / n) for g, c in group["grades"].items()} if n else {},
            "adoption": {k: round(100 * c / n) for k, c in group["counts"].items()} if n else {}}


def compute(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    since = now - timedelta(days=WINDOW_DAYS)
    latest = (db.query(models.Scan.domain, func.max(models.Scan.created_at).label("at"))
              .filter(models.Scan.created_at >= since).group_by(models.Scan.domain).subquery())
    rows = (db.query(models.Scan)
            .join(latest, (models.Scan.domain == latest.c.domain) & (models.Scan.created_at == latest.c.at)))
    overall, by_tld, seen = _empty(), {}, set()
    for scan in rows.yield_per(500):
        if scan.domain in seen:  # two scans with the same timestamp
            continue
        seen.add(scan.domain)
        checks = {c.get("key"): c for c in (scan.result or {}).get("checks", []) if c.get("key")}
        if any(c.get("errored") for c in checks.values()):
            continue  # incomplete scans would skew the numbers
        m = _measures(checks)
        _add(overall, scan, m)
        _add(by_tld.setdefault(scan.domain.rsplit(".", 1)[-1], _empty()), scan, m)
    enough = overall["domains"] >= MIN_TOTAL
    return {"window_days": WINDOW_DAYS, "generated_at": now.isoformat() + "Z", "enough_data": enough,
            "min_group": MIN_GROUP,
            "overall": _publish(overall) if enough else {"domains": overall["domains"]},
            "by_tld": sorted(([{"tld": t, **_publish(g)} for t, g in by_tld.items() if g["domains"] >= MIN_GROUP]
                              if enough else []), key=lambda r: -r["domains"])[:30]}


def cached(db: Session) -> dict:
    hit = _cache.get("v")
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    data = compute(db)
    _cache["v"] = (time.monotonic(), data)
    return data
