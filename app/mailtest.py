""""Send a test email": a signed-in user mails a one-off address
(MAILTEST_ADDRESS with +token), the report-mailbox fetcher picks the message
up, and we store what the receiving server recorded: SPF, DKIM and DMARC
results, alignment, and the delivery path. Only the analysis is kept, never
the message."""
import email
import re
import secrets
from datetime import datetime, timedelta
from email import policy

from sqlalchemy.orm import Session

from . import header_analyzer, models
from .config import settings

TOKEN_BYTES = 6  # 12 hex characters
EXPIRES = timedelta(hours=24)
_RECIPIENT_HEADERS = ("Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To", "X-Forwarded-To",
                      "To", "Cc")


def _parts() -> tuple[str, str] | None:
    addr = settings.MAILTEST_ADDRESS.strip().lower()
    if addr.count("@") != 1 or "+" in addr:
        return None
    local, domain = addr.split("@")
    return (local, domain) if local and domain else None


def is_configured() -> bool:
    if not _parts():
        return False
    from scripts.fetch_dmarc_reports import configured_source
    return configured_source() is not None


def new_token() -> str:
    return secrets.token_hex(TOKEN_BYTES)


def address_for(token: str) -> str:
    local, domain = _parts()
    return f"{local}+{token}@{domain}"


def token_of(msg) -> str | None:
    parts = _parts()
    if not parts:
        return None
    local, domain = parts
    pattern = re.compile(rf"(?<![\w.+-]){re.escape(local)}\+([0-9a-f]{{{TOKEN_BYTES * 2}}})@{re.escape(domain)}\b",
                         re.IGNORECASE)
    for name in _RECIPIENT_HEADERS:
        for value in msg.get_all(name, []) or []:
            m = pattern.search(str(value))
            if m:
                return m.group(1).lower()
    return None


def _header_text(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n")
    return text.split("\n\n", 1)[0][:header_analyzer.MAX_HEADER_BYTES - 1]


def record(db: Session, raw: bytes, now: datetime | None = None) -> bool:
    """File a test message. True when `raw` was addressed to a test address
    (whether or not the test is still waiting), so it isn't treated as a report."""
    msg = email.message_from_bytes(raw[:header_analyzer.MAX_HEADER_BYTES], policy=policy.compat32)
    token = token_of(msg)
    if not token:
        return False
    now = now or datetime.utcnow()
    test = db.query(models.MailTest).filter(models.MailTest.token == token).first()
    if not test or test.received_at is not None or now - test.created_at > EXPIRES:
        return True
    try:
        result = header_analyzer.analyze(_header_text(raw))
    except ValueError as exc:
        result = {"error": str(exc)}
    test.result, test.received_at = result, now
    db.commit()
    return True


def as_dict(test: models.MailTest, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    status = "received" if test.received_at else ("expired" if now - test.created_at > EXPIRES else "waiting")
    return {"token": test.token, "address": address_for(test.token) if _parts() else None, "status": status,
            "created_at": test.created_at.isoformat() + "Z",
            "received_at": test.received_at.isoformat() + "Z" if test.received_at else None,
            "result": test.result}
