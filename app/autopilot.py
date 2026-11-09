"""DMARC enforcement autopilot.

Moves a domain's policy one step at a time (none -> quarantine -> reject) when
aggregate reports show it's safe: at least STEP_PASS_RATE % of mail passes,
no real sending service (approved, or recognised but unaligned) is failing,
and the current stage has held for HOLD_DAYS with reports covering that
span. If real mail starts failing after a step, it steps back one level and
pauses until someone resumes it.

The record is changed where PhishLens can change it: the hosted DMARC record
(app/hosted.py) or, failing that, the company's connected DNS provider (the
change is listed under "Changes made by PhishLens" and can be undone)."""
import logging
import re
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import crypto, dmarc_reports, dns_providers, hosted, mailer, models

log = logging.getLogger("phishlens.autopilot")

LEVELS = ("none", "quarantine", "reject")
HOLD_DAYS = 14
STEP_PASS_RATE = 98.0
MIN_MESSAGES = 100  # enough mail to judge
ROLLBACK_MIN_FAILING = 10  # failing messages from a real sender after a step


class AutopilotError(Exception):
    pass


def _hosted_rec(db: Session, tenant_id: str, domain: str):
    return (db.query(models.HostedRecord)
            .filter_by(tenant_id=tenant_id, domain=domain, kind="dmarc").first())


def mode(db: Session, tenant: models.Tenant, domain: str) -> str | None:
    """How PhishLens can change this domain's DMARC record: hosted | dns | None."""
    if _hosted_rec(db, tenant.id, domain) and hosted.configured():
        return "hosted"
    if tenant.dns_token:
        return "dns"
    return None


def _dns(tenant: models.Tenant, domain: str):
    token = crypto.decrypt(tenant.dns_token)
    if not token:
        raise AutopilotError("Connect your DNS provider first")
    client = dns_providers.client(tenant.dns_provider or "cloudflare", token)
    zone_id, _ = client.zone_for(f"_dmarc.{domain}")
    return client, zone_id


def _policy(value: str) -> str:
    m = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", value, re.I)
    return m.group(1).lower() if m else "none"


def _with_policy(value: str, p: str) -> str:
    """The same record with p= changed (and t=y testing mode dropped)."""
    tags = [t.strip() for t in value.split(";") if t.strip()]
    tags = [t for t in tags if not re.fullmatch(r"t\s*=\s*y", t, re.I)]
    if any(re.match(r"p\s*=", t, re.I) for t in tags):
        tags = [f"p={p}" if re.match(r"p\s*=", t, re.I) else t for t in tags]
    else:
        tags.insert(1, f"p={p}")
    return "; ".join(tags)


def current(db: Session, tenant: models.Tenant, domain: str) -> tuple[str, str | None]:
    """(how, current p=) for the record PhishLens would change."""
    how = mode(db, tenant, domain)
    if how == "hosted":
        return how, _hosted_rec(db, tenant.id, domain).config.get("p", "none")
    if how == "dns":
        client, zone_id = _dns(tenant, domain)
        recs = client.matching(zone_id, f"_dmarc.{domain}", "TXT", "v=DMARC1")
        if not recs:
            raise AutopilotError(f"No DMARC record at _dmarc.{domain} yet: publish one with p=none first")
        return how, _policy(dns_providers._txt_content(recs[0].get("content", "")))
    raise AutopilotError("Autopilot needs hosted DMARC or a connected DNS provider to change the record")


def set_policy(db: Session, tenant: models.Tenant, domain: str, p: str) -> dict:
    """Publish p= for the domain; returns {via, change_id}."""
    how = mode(db, tenant, domain)
    if how == "hosted":
        rec = _hosted_rec(db, tenant.id, domain)
        rec.config = {**rec.config, "p": p, "t": False}
        hosted.publish(rec)
        return {"via": "hosted", "change_id": None}
    if how == "dns":
        client, zone_id = _dns(tenant, domain)
        name = f"_dmarc.{domain}"
        before = [r.get("content", "") for r in client.matching(zone_id, name, "TXT", "v=DMARC1")]
        if not before:
            raise AutopilotError(f"No DMARC record at {name}")
        value = _with_policy(dns_providers._txt_content(before[0]), p)
        client.upsert(zone_id, name, "TXT", value)
        row = models.DnsApplied(tenant_id=tenant.id, user_id=None, provider=tenant.dns_provider or "cloudflare",
                                name=name, rtype="TXT", value=value, previous=before)
        db.add(row)
        db.flush()
        return {"via": "dns", "change_id": row.id}
    raise AutopilotError("Autopilot needs hosted DMARC or a connected DNS provider to change the record")


def _summary(db: Session, tenant_id: str, domain: str, since: datetime) -> dict:
    from .routers.dmarc import sender_rules
    reports = (db.query(models.DmarcReport)
               .filter(models.DmarcReport.tenant_id == tenant_id, models.DmarcReport.domain == domain,
                       models.DmarcReport.date_begin >= since).all())
    days = max(1, (datetime.utcnow() - since).days)
    return dmarc_reports.summarize(reports, domain, days, sender_rules(db, tenant_id, domain))


def _failing_real(summary: dict, min_messages: int) -> list[dict]:
    return [r for r in summary["senders"] if r["category"] in ("approved", "needs_fix")
            and r["failed"] >= min_messages]


def _span(summary: dict) -> int:
    if not summary.get("first") or not summary.get("last"):
        return 0
    first = datetime.fromisoformat(summary["first"].rstrip("Z"))
    last = datetime.fromisoformat(summary["last"].rstrip("Z"))
    return (last - first).days + 1


def decide(db: Session, ap: models.DmarcAutopilot, p: str, now: datetime | None = None) -> dict:
    """What to do now: {action: hold|step|rollback|done, to, reason}."""
    now = now or datetime.utcnow()
    level = LEVELS.index(p) if p in LEVELS else 0
    target = LEVELS.index(ap.target)
    # Real mail failing since the last step: step back.
    if ap.last_step_at and level > 0:
        since = _summary(db, ap.tenant_id, ap.domain, ap.last_step_at)
        failing = _failing_real(since, ROLLBACK_MIN_FAILING)
        if failing:
            names = ", ".join(r["sender"] for r in failing[:3])
            return {"action": "rollback", "to": LEVELS[level - 1],
                    "reason": f"Real mail is failing since p={p}: {names}. Fix DKIM for "
                              f"{'it' if len(failing) == 1 else 'them'}, then resume autopilot."}
    if level >= target:
        return {"action": "done", "to": p, "reason": f"At p={p}: the goal is reached."}
    if ap.last_step_at and now - ap.last_step_at < timedelta(days=HOLD_DAYS):
        left = HOLD_DAYS - (now - ap.last_step_at).days
        return {"action": "hold", "to": p, "reason": f"Holding p={p} for {left} more day(s) to see how mail does."}
    s = _summary(db, ap.tenant_id, ap.domain, now - timedelta(days=HOLD_DAYS + 1))
    if s["messages"] < MIN_MESSAGES:
        return {"action": "hold", "to": p,
                "reason": f"Waiting for more reports ({s['messages']} messages so far, need {MIN_MESSAGES})."}
    if _span(s) < HOLD_DAYS:
        return {"action": "hold", "to": p,
                "reason": f"Waiting for {HOLD_DAYS} days of reports ({_span(s)} so far)."}
    failing = _failing_real(s, 1)
    if failing:
        names = ", ".join(r["sender"] for r in failing[:3])
        return {"action": "hold", "to": p, "reason": f"Waiting for {names} to pass DMARC (turn on DKIM for "
                                                      f"{ap.domain} in its settings)."}
    if (s["pass_rate"] or 0) < STEP_PASS_RATE:
        # Everything failing is unrecognised/blocked, i.e. spoofing: that's what enforcement stops.
        if not any(r["category"] in ("suspicious", "blocked") for r in s["senders"]):
            return {"action": "hold", "to": p, "reason": f"Only {s['pass_rate']}% of mail passes."}
    nxt = LEVELS[level + 1]
    return {"action": "step", "to": nxt,
            "reason": f"{s['pass_rate']}% of mail passed over {_span(s)} days and every real sender is "
                      f"aligned: moving to p={nxt}."}


def _record(ap, frm, to, reason, via, change_id, now):
    ap.history = [*(ap.history or []), {"at": now.isoformat() + "Z", "from": frm, "to": to,
                                        "reason": reason, "via": via, "change_id": change_id}][-50:]


def _email(db, tenant, domain, subject, text):
    to = mailer.team_recipients(db, tenant.id)
    if to:
        mailer.send_email(to, subject, text + f"\n\nDMARC autopilot for {domain}.", tenant=tenant)


def check(db: Session, ap: models.DmarcAutopilot, now: datetime | None = None) -> dict:
    """Evaluate one domain and act. Commits. Returns the decision."""
    now = now or datetime.utcnow()
    tenant = db.get(models.Tenant, ap.tenant_id)
    ap.last_checked_at = now
    try:
        _, p = current(db, tenant, ap.domain)
        d = decide(db, ap, p, now)
        if d["action"] in ("step", "rollback"):
            res = set_policy(db, tenant, ap.domain, d["to"])
            _record(ap, p, d["to"], d["reason"], res["via"], res["change_id"], now)
            ap.last_step_at = now
            if d["action"] == "rollback":
                ap.status = "paused"
                _email(db, tenant, ap.domain, f"DMARC for {ap.domain} stepped back to p={d['to']}", d["reason"])
            else:
                ap.status = "done" if LEVELS.index(d["to"]) >= LEVELS.index(ap.target) else "watching"
                _email(db, tenant, ap.domain, f"DMARC for {ap.domain} moved to p={d['to']}", d["reason"])
        else:
            ap.status = "done" if d["action"] == "done" else "watching"
        ap.message = d["reason"]
    except (AutopilotError, dns_providers.DnsProviderError, hosted.HostedError) as exc:
        d = {"action": "error", "to": None, "reason": str(exc)}
        ap.message = str(exc)
    db.commit()
    return d


def run_all(db: Session) -> dict:
    stats = {"checked": 0, "stepped": 0, "rolled_back": 0}
    for ap in (db.query(models.DmarcAutopilot)
               .filter(models.DmarcAutopilot.enabled.is_(True), models.DmarcAutopilot.status != "paused").all()):
        try:
            d = check(db, ap)
        except Exception:  # one company's failure must not stop the others
            log.exception("autopilot check failed for %s", ap.domain)
            db.rollback()
            continue
        stats["checked"] += 1
        stats["stepped"] += d["action"] == "step"
        stats["rolled_back"] += d["action"] == "rollback"
    return stats
