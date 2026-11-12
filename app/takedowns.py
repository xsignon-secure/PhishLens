"""Takedown tracking: from an abuse report draft to a phishing site that's gone.

1. A draft is written with the registrar's and hosting network's abuse
   addresses from RDAP (phish_reports.takedown). Triage opens drafts by
   itself for links it judged phishing; nothing is sent without a person.
2. Sending emails the abuse addresses from the company's own mail server
   (or the server's), with the person's address as Reply-To. Optionally the
   URL also goes to Netcraft's free reporting API and to APWG.
3. Sent takedowns are rechecked daily. When the domain stops resolving or the
   site stops answering, the team is told it's down; after 3 days still live,
   the team gets one reminder to follow up.

Google Safe Browsing and Microsoft have no free submission API, so the draft
keeps their report forms as links."""
import logging
from datetime import datetime, timedelta

import dns.exception
import dns.resolver
import httpx
from sqlalchemy.orm import Session

from . import mailer, models, phish_reports
from .config import settings
from .scanner import net

log = logging.getLogger("phishlens.takedowns")

NETCRAFT_API = "https://report.netcraft.com/api/v3/report/urls"
APWG = "reportphishing@apwg.org"
FOLLOW_UP_AFTER = timedelta(days=3)
RECHECK_EVERY = timedelta(hours=20)
DOWN_STATUSES = {404, 410, 451}


def out(t: models.Takedown) -> dict:
    return {"id": t.id, "domain": t.domain, "url": t.url, "status": t.status, "auto": bool(t.auto),
            "report_id": t.report_id, "draft": t.draft, "submissions": t.submissions or [],
            "live": t.live, "last_check": t.last_check,
            "sent_at": t.sent_at.isoformat() + "Z" if t.sent_at else None,
            "down_at": t.down_at.isoformat() + "Z" if t.down_at else None,
            "created_by": t.created_by, "created_at": t.created_at.isoformat() + "Z"}


def open_for(db: Session, tenant_id: str, domain: str) -> models.Takedown | None:
    return (db.query(models.Takedown)
            .filter(models.Takedown.tenant_id == tenant_id, models.Takedown.domain == domain,
                    models.Takedown.status.in_(("draft", "sent"))).first())


def create(db: Session, tenant: models.Tenant, domain: str, url: str | None, evidence: list[str],
           report_id: str | None = None, created_by: str | None = None, auto: bool = False,
           draft_fn=None) -> models.Takedown:
    existing = open_for(db, tenant.id, domain)
    if existing:
        return existing
    draft = (draft_fn or phish_reports.takedown)(domain, url, evidence or ["Impersonates our brand"], tenant.name)
    row = models.Takedown(tenant_id=tenant.id, report_id=report_id, domain=draft["domain"], url=url,
                          status="draft", auto=auto, draft=draft, created_by=created_by)
    db.add(row)
    db.commit()
    return row


def _netcraft(email: str, url: str, reason: str, transport=None) -> tuple[bool, str]:
    try:
        with httpx.Client(timeout=15, transport=transport) as c:
            r = c.post(NETCRAFT_API, json={"email": email, "urls": [{"url": url, "reason": reason[:1000]}]})
    except httpx.HTTPError as exc:
        return False, f"Netcraft unreachable: {type(exc).__name__}"
    if r.status_code in (200, 201):
        try:
            uuid = r.json().get("uuid")
        except ValueError:
            uuid = None
        return True, f"Netcraft submission {uuid}" if uuid else "Accepted by Netcraft"
    return False, f"Netcraft answered HTTP {r.status_code}"


def send(db: Session, row: models.Takedown, user: models.User, netcraft: bool = False, apwg: bool = False,
         transport=None) -> models.Takedown:
    """Email the abuse contacts; optionally report to Netcraft and APWG."""
    if row.status not in ("draft", "sent"):
        raise ValueError("This takedown is already closed")
    draft = row.draft or {}
    to = list(draft.get("to") or [])
    if apwg:
        to.append(APWG)
    subs = list(row.submissions or [])
    now = datetime.utcnow().isoformat() + "Z"
    if to:
        cfg = mailer.config_for(user.tenant)
        if not cfg:
            raise ValueError("Set up an email server first (dashboard, Email server), or open the draft in your own mail app")
        msg = mailer.build_message(cfg, to, draft.get("subject") or f"Phishing report: {row.domain}",
                                   draft.get("body") or "", prefix=False)
        if mailer.real_email(user.email):
            msg["Reply-To"] = user.email
        try:
            mailer.deliver(cfg, msg)
            subs.append({"target": ", ".join(to), "at": now, "ok": True, "detail": "Emailed"})
        except mailer.SmtpError as exc:
            subs.append({"target": ", ".join(to), "at": now, "ok": False, "detail": str(exc)[:200]})
    if netcraft:
        url = row.url or f"http://{row.domain}/"
        ok, detail = _netcraft(user.email, url, f"Phishing site impersonating {user.tenant.name}", transport)
        subs.append({"target": "Netcraft", "at": now, "ok": ok, "detail": detail})
    if not any(s.get("ok") for s in subs[len(row.submissions or []):]):
        row.submissions = subs
        db.commit()
        raise ValueError("Nothing was sent: no abuse address was found and no other report was chosen"
                         if not to and not netcraft else "Sending failed; see the submission log")
    row.submissions = subs
    row.status = "sent"
    row.sent_at = row.sent_at or datetime.utcnow()
    db.commit()
    return row


def check_live(domain: str, url: str | None = None) -> dict:
    """{live, reason}: is the phishing site still up?"""
    try:
        dns.resolver.resolve(domain, "A", lifetime=6)
    except dns.resolver.NXDOMAIN:
        return {"live": False, "reason": "The domain no longer exists (suspended or deleted)."}
    except dns.resolver.NoAnswer:
        return {"live": False, "reason": "The domain no longer points at a web server."}
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return {"live": None, "reason": "DNS didn't answer; will try again."}
    target = url or f"http://{domain}/"
    try:
        r = net.safe_get(target, timeout=8)
    except ValueError:
        return {"live": False, "reason": "The domain no longer points at a public server."}
    except httpx.HTTPError as exc:
        return {"live": False, "reason": f"The site doesn't answer ({type(exc).__name__})."}
    if r.status_code in DOWN_STATUSES:
        return {"live": False, "reason": f"The page is gone (HTTP {r.status_code})."}
    return {"live": True, "reason": f"Still online (HTTP {r.status_code})."}


def record_check(db: Session, row: models.Takedown, result: dict) -> bool:
    """Save a check; returns True when this check found the site newly down."""
    row.last_check = {"at": datetime.utcnow().isoformat() + "Z", **result}
    if result["live"] is None:
        db.commit()
        return False
    row.live = result["live"]
    newly_down = result["live"] is False and row.status == "sent"
    if newly_down:
        row.status = "down"
        row.down_at = datetime.utcnow()
    db.commit()
    return newly_down


def recheck_all(db: Session, check=check_live, now: datetime | None = None) -> dict:
    """Daily: recheck sent takedowns; tell the team when one is down, and
    remind them once when one is still live after FOLLOW_UP_AFTER."""
    now = now or datetime.utcnow()
    rows = db.query(models.Takedown).filter(models.Takedown.status == "sent").all()
    stats = {"checked": 0, "down": 0, "reminded": 0}
    for row in rows:
        last = (row.last_check or {}).get("at")
        if last:
            try:
                if now - datetime.fromisoformat(last.rstrip("Z")) < RECHECK_EVERY:
                    continue
            except ValueError:
                pass
        try:
            result = check(row.domain, row.url)
        except Exception:
            log.exception("takedown recheck failed for %s", row.domain)
            continue
        stats["checked"] += 1
        tenant = db.get(models.Tenant, row.tenant_id)
        team = mailer.team_recipients(db, row.tenant_id)
        if record_check(db, row, result):
            stats["down"] += 1
            mailer.send_email(team, f"Phishing site taken down: {row.domain}",
                              f"{row.domain} is down: {result['reason']}\n\nReported on "
                              f"{row.sent_at:%Y-%m-%d}. Nothing else to do.\n", tenant=tenant)
        elif row.live and row.sent_at and now - row.sent_at >= FOLLOW_UP_AFTER and not row.followed_up_at:
            row.followed_up_at = now
            db.commit()
            stats["reminded"] += 1
            mailer.send_email(team, f"Phishing site still online: {row.domain}",
                              f"{row.domain} is still online {(now - row.sent_at).days} days after the abuse report.\n"
                              "Send the report again, or use the registrar's and host's abuse web forms, "
                              f"and report it to Google Safe Browsing.\n\n{settings.APP_URL.rstrip('/')}/dashboard#reports\n",
                              tenant=tenant)
    return stats
