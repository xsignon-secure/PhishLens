#!/usr/bin/env python3
"""Pull DMARC aggregate and failure reports from a mailbox and file them per tenant.

Point each customer domain's DMARC record at one shared report mailbox, e.g.
    _dmarc.example.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@reports.yourdomain.com; ruf=mailto:dmarc@reports.yourdomain.com; fo=1"
then run this from cron (hourly is plenty):

    15 * * * *  cd /srv/phishlens && .venv/bin/python scripts/fetch_dmarc_reports.py

Configure with DMARC_IMAP_HOST, DMARC_IMAP_USER, DMARC_IMAP_PASSWORD
(optional DMARC_IMAP_FOLDER, default INBOX). Each report is stored for every
tenant that monitors the report's domain; reports for unmonitored domains are
skipped. Processed messages are marked \\Seen so they are not fetched twice.

Reporting to an address on a different domain needs one extra record on the
customer's side (RFC 7489 section 7.1), published in YOUR zone:
    example.com._report._dmarc.reports.yourdomain.com  TXT  "v=DMARC1"
"""
import email
import imaplib
import os
import sys
from email import policy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import dmarc_reports, forensic, models  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.routers.dmarc import store_report  # noqa: E402

_REPORT_TYPES = ("application/zip", "application/gzip", "application/x-gzip",
                 "application/x-zip-compressed", "text/xml", "application/xml",
                 "application/octet-stream")


def attachments(msg) -> list[bytes]:
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = (part.get_filename() or "").lower()
        if part.get_content_type() in _REPORT_TYPES or name.endswith((".xml", ".gz", ".zip")):
            payload = part.get_payload(decode=True)
            if payload:
                out.append(payload)
    return out


def _tenants_for(db, domain: str) -> list[str]:
    return [t for (t,) in db.query(models.Monitor.tenant_id)
            .filter(models.Monitor.domain == domain, models.Monitor.is_active.is_(True)).distinct()]


def file_message(db, raw: bytes) -> tuple[int, int]:
    """Store every report in one email (aggregate attachments, or a failure
    report). Returns (stored, skipped)."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    stored = skipped = 0
    if forensic.is_arf(msg):
        try:
            parsed = forensic.parse(raw)
        except forensic.ForensicError:
            return 0, 1
        tenants = _tenants_for(db, parsed["domain"])
        for tenant_id in tenants:
            _, created = forensic.store(db, tenant_id, parsed)
            stored += int(created)
        return stored, 0 if tenants else 1
    for blob in attachments(msg):
        try:
            parsed = dmarc_reports.parse(blob)
        except dmarc_reports.ReportError:
            skipped += 1
            continue
        tenants = _tenants_for(db, parsed["domain"])
        if not tenants:
            skipped += 1
            continue
        for tenant_id in tenants:
            _, created = store_report(db, tenant_id, parsed)
            stored += int(created)
    return stored, skipped


def main() -> int:
    host, user = os.environ.get("DMARC_IMAP_HOST"), os.environ.get("DMARC_IMAP_USER")
    password = os.environ.get("DMARC_IMAP_PASSWORD")
    if not (host and user and password):
        print("Set DMARC_IMAP_HOST, DMARC_IMAP_USER and DMARC_IMAP_PASSWORD", file=sys.stderr)
        return 2
    init_db()
    db = SessionLocal()
    stored = skipped = 0
    try:
        with imaplib.IMAP4_SSL(host) as imap:
            imap.login(user, password)
            imap.select(os.environ.get("DMARC_IMAP_FOLDER", "INBOX"))
            _, data = imap.search(None, "UNSEEN")
            for num in data[0].split():
                _, fetched = imap.fetch(num, "(RFC822)")
                raw = next((p[1] for p in fetched if isinstance(p, tuple)), None)
                if raw:
                    s, k = file_message(db, raw)
                    stored, skipped = stored + s, skipped + k
                imap.store(num, "+FLAGS", "\\Seen")
    finally:
        db.close()
    print(f"stored={stored} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
