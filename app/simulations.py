"""Phishing simulations: send staff a harmless practice phishing email and
see who clicks and who reports it.

Safeguards, all enforced on the server:

- Only a company owner can launch, after re-entering their authenticator
  code, and must confirm they are authorised to test these people. Who
  confirmed, and when, is stored with the campaign and in the audit log.
- Recipients must be on a domain the company has proved it controls: a TXT
  record at _phishlens-sim.<domain>, or a verified domain of the connected
  Microsoft 365 / Google Workspace tenant. Proof is re-checked at launch.
- Mail goes out only through the company's own mail server (Dashboard →
  Email server), from its own address, never through this service's mail
  server, so the hosted service never sends phishing-like mail itself.
- Built-in templates only: generic senders, no real brands or people, no
  attachments. The landing page never has a form and never asks for a
  password; it says it was a test and shows the warning signs.
- Every message carries an X-PhishLens-Simulation header so mail admins can
  recognise (and allow-list) it, and reports of it through the report button
  count as "reported" instead of opening a real incident.
- At most 500 recipients per campaign and 5 campaigns a day.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from sqlalchemy.orm import Session

from . import mailer, models
from .config import settings

log = logging.getLogger("phishlens.simulations")

MAX_RECIPIENTS = 500
MAX_PER_DAY = 5
HEADER = "X-PhishLens-Simulation"
TXT_LABEL = "_phishlens-sim"
TOKEN_RE = re.compile(r"/s/([A-Za-z0-9_-]{20,64})")

# Generic, brand-free lures. {link} is the tracked link, {company} the
# company's name. "signs" are shown on the landing page afterwards.
TEMPLATES = {
    "password_expiry": {
        "name": "Password expires today",
        "difficulty": "easy",
        "from_name": "IT Service Desk",
        "subject": "Action required: your password expires today",
        "body": ("Hello,\n\nYour network password expires in 2 hours. To avoid losing access to email "
                 "and files, keep your current password now:\n\n{link}\n\nIf you do nothing, your "
                 "account will be locked.\n\nIT Service Desk"),
        "button": "Keep my current password",
        "signs": ["A deadline of a few hours, with a threat to lock your account.",
                  "\"Hello\" instead of your name.",
                  "The link goes to a website that isn't your company's sign-in page.",
                  "IT teams don't ask you to keep a password through an email link."],
    },
    "shared_document": {
        "name": "Shared document",
        "difficulty": "medium",
        "from_name": "Document Sharing",
        "subject": "\"Salary review 2027.xlsx\" was shared with you",
        "body": ("A colleague shared a file with you.\n\nSalary review 2027.xlsx\n\nOpen it here:\n\n{link}\n\n"
                 "This link will expire in 24 hours."),
        "button": "Open document",
        "signs": ["A tempting file name (salaries) you weren't expecting.",
                  "It doesn't say which colleague shared it.",
                  "Real sharing notices come from the app your company uses, and you can find the file there yourself.",
                  "Pressure: the link \"expires in 24 hours\"."],
    },
    "delivery": {
        "name": "Missed parcel",
        "difficulty": "easy",
        "from_name": "Parcel Delivery",
        "subject": "We couldn't deliver your parcel",
        "body": ("Hello,\n\nWe tried to deliver your parcel today but nobody was available. Choose a new "
                 "delivery time here:\n\n{link}\n\nParcels not rescheduled within 48 hours are returned "
                 "to the sender."),
        "button": "Reschedule delivery",
        "signs": ["No carrier name, tracking number or sender of the parcel.",
                  "You may not be expecting a parcel at work at all.",
                  "A deadline and a threat (the parcel is returned).",
                  "Check deliveries on the carrier's own website, never from a link."],
    },
    "invoice": {
        "name": "Overdue invoice",
        "difficulty": "medium",
        "from_name": "Accounts Receivable",
        "subject": "Overdue invoice 48213: payment due today",
        "body": ("Hello,\n\nInvoice 48213 for services to {company} is now 30 days overdue. Please review "
                 "it and confirm payment today to avoid a late fee:\n\n{link}\n\nKind regards,\n"
                 "Accounts Receivable"),
        "button": "View invoice",
        "signs": ["An unknown supplier with no company name or contact details.",
                  "Urgency and a penalty (late fee).",
                  "Invoices should be checked against a purchase order, not opened from an email link.",
                  "Payment or bank detail changes must be confirmed by phone with a known contact."],
    },
    "unusual_signin": {
        "name": "Unusual sign-in",
        "difficulty": "hard",
        "from_name": "Account Security",
        "subject": "Unusual sign-in to your account",
        "body": ("We noticed a sign-in to your account from a new device.\n\nLocation: Lagos, Nigeria\n"
                 "Device: Windows 10, Chrome\n\nIf this wasn't you, secure your account now:\n\n{link}\n\n"
                 "Account Security"),
        "button": "Secure my account",
        "signs": ["It plays on fear: a stranger in your account.",
                  "It doesn't say which account or service.",
                  "The \"secure my account\" link goes to an unfamiliar website.",
                  "If you are worried, go to the service yourself or call your IT team."],
    },
}


# ------------------------------------------------------------------ domains
def verify_value(tenant_id: str) -> str:
    mac = hmac.new(settings.SECRET_KEY.encode(), f"sim|{tenant_id}".encode(), hashlib.sha256).hexdigest()
    return "phishlens-sim=" + mac[:32]


def _txt(name: str) -> list[str]:
    from .scanner.dns_checks import _resolver
    try:
        return [b"".join(r.strings).decode(errors="replace") for r in _resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []


def _cloud_domains(tenant: models.Tenant) -> set[str]:
    out = set()
    for kind in ("m365", "gws"):
        res = ((tenant.posture or {}).get(kind) or {}).get("result") or {}
        out |= {d.lower() for d in res.get("domains") or []}
    return out


def proof(tenant: models.Tenant, domain: str, txt=None) -> str | None:
    """How the company proves it controls `domain`, or None."""
    txt = txt or _txt
    domain = domain.lower().strip(".")
    if domain in _cloud_domains(tenant):
        return "cloud"
    if verify_value(tenant.id) in [t.strip() for t in txt(f"{TXT_LABEL}.{domain}")]:
        return "dns"
    return None


def verified(tenant: models.Tenant) -> dict:
    return dict(tenant.sim_domains or {})


# ------------------------------------------------------------------ campaigns
def parse_recipients(text: str) -> list[str]:
    seen, out = set(), []
    for raw in re.split(r"[\s,;]+", text or ""):
        e = raw.strip().strip("<>").lower()
        if not e:
            continue
        if not re.fullmatch(r"[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}", e) or len(e) > 254:
            raise ValueError(f"Not an email address: {raw[:80]}")
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def recipient_domain_ok(email: str, domains: set[str]) -> bool:
    d = email.rsplit("@", 1)[1]
    return any(d == v or d.endswith("." + v) for v in domains)


def campaigns_today(db: Session, tenant_id: str, now: datetime) -> int:
    return (db.query(models.SimCampaign)
            .filter(models.SimCampaign.tenant_id == tenant_id,
                    models.SimCampaign.created_at >= now - timedelta(days=1)).count())


def new_token() -> str:
    return secrets.token_urlsafe(24)


def link_for(token: str) -> str:
    return settings.APP_URL.rstrip("/") + "/s/" + token


def build(cfg: dict, tenant: models.Tenant, campaign: models.SimCampaign, rcpt: models.SimRecipient) -> EmailMessage:
    t = TEMPLATES[campaign.template]
    link = link_for(rcpt.token)
    company = tenant.name or "your company"
    text = t["body"].format(link=link, company=company)
    msg = EmailMessage()
    msg["Subject"] = t["subject"]
    msg["From"] = formataddr((t["from_name"], cfg["from_address"]))
    msg["To"] = rcpt.email
    msg["Message-ID"] = make_msgid(domain=cfg["from_address"].rsplit("@", 1)[-1])
    msg[HEADER] = campaign.id
    msg.set_content(text)
    paras = "".join(
        f'<p><a href="{link}" style="display:inline-block;background:#1f5bd8;color:#fff;padding:10px 16px;'
        f'border-radius:6px;text-decoration:none">{_h(t["button"])}</a></p>' if p.strip() == link
        else "<p>" + _h(p).replace("\n", "<br>") + "</p>"
        for p in text.split("\n\n"))
    msg.add_alternative(f'<div style="font:14px/1.5 Arial,sans-serif;color:#222">{paras}</div>', subtype="html")
    return msg


def _h(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def send(db: Session, campaign_id: str, deliver=None) -> dict:
    """Send a campaign's emails (runs in the background after launch)."""
    deliver = deliver or mailer.deliver
    c = db.get(models.SimCampaign, campaign_id)
    if not c or c.status != "sending":
        return {"sent": 0, "failed": 0}
    tenant = db.get(models.Tenant, c.tenant_id)
    cfg = mailer.tenant_config(tenant)
    sent = failed = 0
    rows = (db.query(models.SimRecipient)
            .filter(models.SimRecipient.campaign_id == c.id, models.SimRecipient.sent_at.is_(None),
                    models.SimRecipient.error.is_(None)).all())
    for r in rows:
        if not cfg:
            r.error = "The company's mail server was removed"
            failed += 1
            continue
        try:
            deliver(cfg, build(cfg, tenant, c, r))
            r.sent_at = datetime.utcnow()
            sent += 1
        except Exception as exc:  # one bad address must not stop the rest
            r.error = str(exc)[:300]
            failed += 1
        db.commit()
    c.status = "failed" if failed and not sent else "sent"
    c.finished_at = datetime.utcnow()
    db.commit()
    log.info("simulation %s: sent %s, failed %s", c.id, sent, failed)
    return {"sent": sent, "failed": failed}


def send_in_background(campaign_id: str) -> None:
    from .database import SessionLocal
    db = SessionLocal()
    try:
        send(db, campaign_id)
    except Exception:
        log.exception("simulation %s failed", campaign_id)
    finally:
        db.close()


def stats(db: Session, campaign: models.SimCampaign) -> dict:
    rows = db.query(models.SimRecipient).filter(models.SimRecipient.campaign_id == campaign.id).all()
    sent = [r for r in rows if r.sent_at]
    n = len(sent) or 1
    clicked = sum(1 for r in sent if r.clicked_at)
    reported = sum(1 for r in sent if r.reported_at)
    return {"recipients": len(rows), "sent": len(sent), "failed": sum(1 for r in rows if r.error),
            "clicked": clicked, "reported": reported,
            "click_rate": round(100 * clicked / n), "report_rate": round(100 * reported / n)}


# ------------------------------------------------------------------ tracking
def recipient_for_token(db: Session, token: str) -> models.SimRecipient | None:
    if not token or len(token) > 64:
        return None
    return db.query(models.SimRecipient).filter(models.SimRecipient.token == token).first()


def match_report(db: Session, tenant_id: str, parsed: dict) -> models.SimRecipient | None:
    """A reported email that is one of this company's simulations, if any."""
    base = settings.APP_URL.rstrip("/")
    for u in parsed.get("urls") or []:
        if not u.startswith(base + "/s/"):
            continue
        m = TOKEN_RE.search(u[len(base):])
        r = recipient_for_token(db, m.group(1)) if m else None
        if r and r.tenant_id == tenant_id:
            return r
    return None
