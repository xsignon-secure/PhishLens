#!/usr/bin/env python3
"""Pull DMARC aggregate, DMARC failure and SMTP TLS (TLS-RPT) reports from a
mailbox and file them per tenant.

Point each customer domain's DMARC record at one shared report mailbox, e.g.
    _dmarc.example.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@reports.yourdomain.com; ruf=mailto:dmarc@reports.yourdomain.com; fo=1"
then run this from cron (hourly is plenty):

    15 * * * *  cd /srv/phishlens && .venv/bin/python scripts/fetch_dmarc_reports.py

Point TLS-RPT at the same mailbox:
    _smtp._tls.example.com  TXT  "v=TLSRPTv1; rua=mailto:dmarc@reports.yourdomain.com"

Mailbox sources (configure one; the built-in scheduler also runs this when
REPORT_FETCH_MINUTES is set):
- IMAP: DMARC_IMAP_HOST, DMARC_IMAP_USER, DMARC_IMAP_PASSWORD (DMARC_IMAP_FOLDER).
- Microsoft 365 (Graph, app-only): DMARC_GRAPH_TENANT_ID, DMARC_GRAPH_CLIENT_ID,
  DMARC_GRAPH_CLIENT_SECRET, DMARC_GRAPH_MAILBOX. The app registration needs the
  Mail.ReadWrite application permission (scope it to this mailbox with an
  application access policy).
- Gmail API: DMARC_GMAIL_CLIENT_ID, DMARC_GMAIL_CLIENT_SECRET,
  DMARC_GMAIL_REFRESH_TOKEN (scope https://www.googleapis.com/auth/gmail.modify).

Each report is stored for every tenant that monitors the report's domain;
reports for unmonitored domains are skipped. Processed messages are marked
read so they are not fetched twice.

Reporting to an address on a different domain needs one extra record on the
customer's side (RFC 9990 external reporting), published in YOUR zone:
    example.com._report._dmarc.reports.yourdomain.com  TXT  "v=DMARC1"
"""
import base64
import email
import imaplib
import os
import sys
from collections.abc import Iterator
from email import policy
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import dmarc_reports, forensic, models, tls_reports  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.routers.dmarc import store_report  # noqa: E402

_REPORT_TYPES = ("application/zip", "application/gzip", "application/x-gzip",
                 "application/x-zip-compressed", "text/xml", "application/xml",
                 "application/octet-stream", "application/tlsrpt+gzip", "application/tlsrpt+json",
                 "application/json")


def attachments(msg) -> list[bytes]:
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = (part.get_filename() or "").lower()
        if part.get_content_type() in _REPORT_TYPES or name.endswith((".xml", ".gz", ".zip", ".json")):
            payload = part.get_payload(decode=True)
            if payload:
                out.append(payload)
    return out


def _tenants_for(db, domain: str) -> list[str]:
    return [t for (t,) in db.query(models.Monitor.tenant_id)
            .filter(models.Monitor.domain == domain, models.Monitor.is_active.is_(True)).distinct()]


def _is_tlsrpt(blob: bytes) -> bool:
    """TLS-RPT reports are JSON (often gzipped); DMARC reports are XML."""
    import gzip
    import io
    head = blob
    if blob[:2] == b"\x1f\x8b":
        try:
            head = gzip.GzipFile(fileobj=io.BytesIO(blob)).read(64)
        except (OSError, EOFError):
            return False
    return head[:64].lstrip()[:1] == b"{"


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
        if _is_tlsrpt(blob):
            try:
                parsed = tls_reports.parse(blob)
            except tls_reports.TlsReportError:
                skipped += 1
                continue
            tenants = _tenants_for(db, parsed["domain"])
            for tenant_id in tenants:
                _, created = tls_reports.store(db, tenant_id, parsed)
                stored += int(created)
            skipped += 0 if tenants else 1
            continue
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


# ------------------------------------------------------------------ mailbox sources
def imap_messages() -> Iterator[bytes]:
    host, user = os.environ.get("DMARC_IMAP_HOST"), os.environ.get("DMARC_IMAP_USER")
    with imaplib.IMAP4_SSL(host) as imap:
        imap.login(user, os.environ["DMARC_IMAP_PASSWORD"])
        imap.select(os.environ.get("DMARC_IMAP_FOLDER", "INBOX"))
        _, data = imap.search(None, "UNSEEN")
        for num in data[0].split():
            _, fetched = imap.fetch(num, "(RFC822)")
            raw = next((p[1] for p in fetched if isinstance(p, tuple)), None)
            if raw:
                yield raw
            imap.store(num, "+FLAGS", "\\Seen")


GRAPH = "https://graph.microsoft.com/v1.0"


def graph_messages(client: httpx.Client | None = None) -> Iterator[bytes]:
    """Unread mail from a Microsoft 365 mailbox through Microsoft Graph
    (works where IMAP basic auth is disabled)."""
    env = os.environ
    client = client or httpx.Client(timeout=30)
    tok = client.post(f"https://login.microsoftonline.com/{env['DMARC_GRAPH_TENANT_ID']}/oauth2/v2.0/token",
                      data={"grant_type": "client_credentials", "client_id": env["DMARC_GRAPH_CLIENT_ID"],
                            "client_secret": env["DMARC_GRAPH_CLIENT_SECRET"],
                            "scope": "https://graph.microsoft.com/.default"}).json()
    if "access_token" not in tok:
        raise RuntimeError(f"Microsoft sign-in failed: {tok.get('error_description') or tok.get('error')}")
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    box = f"{GRAPH}/users/{env['DMARC_GRAPH_MAILBOX']}"
    url = f"{box}/mailFolders/inbox/messages?$filter=isRead eq false&$select=id&$top=50"
    for _ in range(20):  # up to 1,000 messages per run
        page = client.get(url, headers=h).json()
        for m in page.get("value", []):
            r = client.get(f"{box}/messages/{m['id']}/$value", headers=h)
            if r.status_code == 200:
                yield r.content
            client.patch(f"{box}/messages/{m['id']}", headers=h, json={"isRead": True})
        url = page.get("@odata.nextLink")
        if not url:
            break


GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"


def gmail_messages(client: httpx.Client | None = None) -> Iterator[bytes]:
    """Unread mail from a Gmail / Google Workspace mailbox through the Gmail API."""
    env = os.environ
    client = client or httpx.Client(timeout=30)
    tok = client.post("https://oauth2.googleapis.com/token", data={
        "grant_type": "refresh_token", "client_id": env["DMARC_GMAIL_CLIENT_ID"],
        "client_secret": env["DMARC_GMAIL_CLIENT_SECRET"],
        "refresh_token": env["DMARC_GMAIL_REFRESH_TOKEN"]}).json()
    if "access_token" not in tok:
        raise RuntimeError(f"Google sign-in failed: {tok.get('error_description') or tok.get('error')}")
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    params = {"q": "is:unread", "maxResults": 100}
    for _ in range(10):
        page = client.get(f"{GMAIL}/messages", headers=h, params=params).json()
        for m in page.get("messages", []):
            raw = client.get(f"{GMAIL}/messages/{m['id']}", headers=h, params={"format": "raw"}).json().get("raw")
            if raw:
                yield base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            client.post(f"{GMAIL}/messages/{m['id']}/modify", headers=h, json={"removeLabelIds": ["UNREAD"]})
        if not page.get("nextPageToken"):
            break
        params["pageToken"] = page["nextPageToken"]


def _load_env_file() -> None:
    """Settings read .env themselves; this script reads os.environ, so load it too."""
    from dotenv import load_dotenv

    from app.config import ENV_FILE
    load_dotenv(ENV_FILE, override=False)


def configured_source():
    _load_env_file()
    env = os.environ
    if env.get("DMARC_GRAPH_TENANT_ID") and env.get("DMARC_GRAPH_MAILBOX"):
        return graph_messages
    if env.get("DMARC_GMAIL_REFRESH_TOKEN"):
        return gmail_messages
    if env.get("DMARC_IMAP_HOST") and env.get("DMARC_IMAP_USER") and env.get("DMARC_IMAP_PASSWORD"):
        return imap_messages
    return None


def run() -> dict | None:
    """Fetch and file reports once. None when no mailbox is configured."""
    source = configured_source()
    if not source:
        return None
    init_db()
    db = SessionLocal()
    stored = skipped = 0
    try:
        for raw in source():
            s, k = file_message(db, raw)
            stored, skipped = stored + s, skipped + k
    finally:
        db.close()
    return {"stored": stored, "skipped": skipped}


def main() -> int:
    stats = run()
    if stats is None:
        print("Configure a mailbox: DMARC_IMAP_*, DMARC_GRAPH_* or DMARC_GMAIL_* (see this file's header)",
              file=sys.stderr)
        return 2
    print(f"stored={stats['stored']} skipped={stats['skipped']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
