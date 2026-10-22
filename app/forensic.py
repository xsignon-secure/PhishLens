"""DMARC failure (forensic / RUF) reports in Abuse Reporting Format (RFC 6591).

Each one describes a single message that failed DMARC: where it came from
and which check failed. They're the fastest way to see an active spoofing
campaign. Only the report fields and the failing message's From / Subject are
kept: the message body is discarded, since it can contain the recipient's
private mail.
"""
import hashlib
import ipaddress
from email import message_from_bytes, policy
from email.parser import HeaderParser
from email.utils import parseaddr, parsedate_to_datetime

MAX_BYTES = 5 * 1024 * 1024


class ForensicError(ValueError):
    pass


def is_arf(msg) -> bool:
    return (msg.get_content_type() == "multipart/report"
            and (msg.get_param("report-type") or "").lower() == "feedback-report")


def _fields(part) -> dict:
    payload = part.get_payload()
    if isinstance(payload, list):  # parsed as message/* with sub-parts
        text = "".join(str(p) for p in payload)
    else:
        raw = part.get_payload(decode=True)
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(payload)
    hdrs = HeaderParser().parsestr(text.strip() + "\n\n", headersonly=True)
    return {k.lower(): str(v) for k, v in hdrs.items()}


def parse(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        raise ForensicError("Report is too large (5 MB max)")
    msg = message_from_bytes(raw, policy=policy.compat32)
    if not is_arf(msg):
        raise ForensicError("Not a DMARC failure report (expected multipart/report; report-type=feedback-report)")
    fields, original = {}, None
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/feedback-report":
            fields = _fields(part)
        elif ctype in ("message/rfc822", "text/rfc822-headers", "message/rfc822-headers") and original is None:
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                original = payload[0]
            else:
                body = part.get_payload(decode=True) or b""
                original = HeaderParser().parsestr(body.decode("utf-8", "replace").split("\n\n", 1)[0] + "\n\n",
                                                   headersonly=True)
    if not fields:
        raise ForensicError("Report has no machine-readable feedback part")
    domain = (fields.get("reported-domain") or "").lower().strip().rstrip(".")
    header_from = parseaddr(str(original.get("From", "")))[1].lower() if original is not None else ""
    if not domain and "@" in header_from:
        domain = header_from.rsplit("@", 1)[1]
    if not domain:
        raise ForensicError("Report doesn't name the domain")
    ip = (fields.get("source-ip") or "").strip()
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        ip = None
    arrival = None
    if fields.get("arrival-date"):
        try:
            arrival = parsedate_to_datetime(fields["arrival-date"]).replace(tzinfo=None)
        except (TypeError, ValueError):
            arrival = None
    subject = str(original.get("Subject", ""))[:300] if original is not None else None
    reporter = parseaddr(str(msg.get("From", "")))[1].rsplit("@", 1)[-1][:200] or None
    out = {
        "domain": domain, "reporter": reporter, "source_ip": ip, "arrival_date": arrival,
        "auth_failure": (fields.get("auth-failure") or "")[:100] or None,
        "delivery_result": (fields.get("delivery-result") or "")[:50] or None,
        "original_mail_from": (fields.get("original-mail-from") or "").strip("<> ")[:320] or None,
        "header_from": header_from[:320] or None, "subject": subject or None,
        "auth_results": (fields.get("authentication-results") or "")[:2000] or None,
    }
    key = "|".join(str(out[k]) for k in ("domain", "source_ip", "arrival_date", "header_from", "subject"))
    key += "|" + str(msg.get("Message-ID", ""))
    out["fingerprint"] = hashlib.sha256(key.encode()).hexdigest()
    return out


def store(db, tenant_id: str, parsed: dict):
    from . import models

    existing = (db.query(models.ForensicReport)
                .filter(models.ForensicReport.tenant_id == tenant_id,
                        models.ForensicReport.fingerprint == parsed["fingerprint"]).first())
    if existing:
        return existing, False
    row = models.ForensicReport(tenant_id=tenant_id, **parsed)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, True
