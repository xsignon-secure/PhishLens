"""The company's threat feed: phishing domains, URLs and sender addresses
PhishLens found, as STIX 2.1 indicators for SIEMs (Microsoft Sentinel,
Splunk, Elastic, QRadar, OpenCTI, MISP…) and firewall block lists.

Sources, each with a confidence:

- registered lookalikes of a monitored domain (anomalous; raised when the
  site copies the company's look, asks for a password, or receives mail);
- phishing links in reports from staff (malicious when the link checker or
  an admin says so; clean links and links to the company's own domains are
  never included);
- the sender address of a report an admin confirmed as phishing;
- takedown requests (malicious).

Indicators get a stable STIX id per company and value. When a source stops
listing one (a lookalike lapses, a report is marked a false positive, a
takedown is closed) it stays in the feed as revoked, so a SIEM that already
pulled it drops it.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import models

NAMESPACE = uuid.UUID("5d0f7b0e-6a49-4c1e-9c43-6f0e2b7a1c55")
COLLECTION_ID = "0b5e2a3c-9f7d-4c6b-8e1a-7d3f4c2b1a90"  # one collection; the API key picks the company
REPORT_DAYS = 90
BAD_LINKS = {"dangerous", "likely phishing"}
KINDS = ("domain", "url", "email")


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def stix_id(tenant_id: str, kind: str, value: str) -> str:
    return "indicator--" + str(uuid.uuid5(NAMESPACE, f"{tenant_id}|{kind}|{value}"))


def identity_id(tenant_id: str) -> str:
    return "identity--" + str(uuid.uuid5(NAMESPACE, f"{tenant_id}|identity"))


def _own(value: str, own: set[str]) -> bool:
    v = value.lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in own)


# ------------------------------------------------------------------ collecting
def collect(db: Session, tenant: models.Tenant, now: datetime | None = None) -> dict:
    """What the feed should hold right now: {(kind, value): {...}}."""
    now = now or datetime.utcnow()
    monitors = db.query(models.Monitor).filter(models.Monitor.tenant_id == tenant.id).all()
    own = {m.domain.lower() for m in monitors}
    out: dict[tuple[str, str], dict] = {}

    def add(kind, value, source, confidence, malicious, note):
        value = (value or "").strip()
        if not value or len(value) > 2000:
            return
        if kind != "url":
            value = value.lower().rstrip(".")
        host = value.rsplit("@", 1)[-1] if kind == "email" else value
        if kind == "url":
            from urllib.parse import urlparse
            host = (urlparse(value).hostname or "")
            if not host:
                return
        if _own(host, own):
            return  # never ask a SIEM to block the company's own domains
        row = out.setdefault((kind, value), {"sources": [], "confidence": 0, "malicious": False, "notes": []})
        if source not in row["sources"]:
            row["sources"].append(source)
        row["confidence"] = max(row["confidence"], confidence)
        row["malicious"] = row["malicious"] or malicious
        if note not in row["notes"]:
            row["notes"].append(note)

    for m in monitors:
        visual = m.lookalike_visual or {}
        certs = ((m.ct_state or {}).get("lookalike_max_id") or {})
        for look in m.lookalikes or []:
            v = (visual.get(look) or {})
            conf, why = 40, [f"Registered lookalike of {m.domain}"]
            if v.get("verdict") == "impersonating":
                conf, why = 85, why + ["its website copies the real one"]
            elif v.get("verdict") == "suspicious":
                conf, why = 60, why + ["its website resembles the real one"]
            if v.get("login_form"):
                conf, why = max(conf, 70), why + ["it asks for a password"]
            if certs.get(look):
                conf, why = min(conf + 10, 95), why + ["it has a TLS certificate"]
            add("domain", look, "lookalike", conf, v.get("verdict") == "impersonating", ", ".join(why) + ".")

    since = now - timedelta(days=REPORT_DAYS)
    reports = (db.query(models.PhishReport)
               .filter(models.PhishReport.tenant_id == tenant.id, models.PhishReport.created_at >= since,
                       models.PhishReport.status != "false_positive").all())
    for r in reports:
        confirmed = r.status == "confirmed"
        for link in r.links or []:
            verdict = link.get("verdict")
            if verdict in BAD_LINKS or (confirmed and verdict == "suspicious"):
                bad = verdict == "dangerous" or confirmed
                conf = 90 if verdict == "dangerous" else 80 if confirmed else 65
                note = f"Link in a reported phishing email ({verdict}{', confirmed by an admin' if confirmed else ''})."
                if link.get("url"):
                    add("url", link["url"], "phish_report", conf, bad, note)
                if link.get("domain"):
                    add("domain", link["domain"], "phish_report", conf, bad, note)
        if confirmed and r.sender:
            from email.utils import parseaddr
            addr = parseaddr(r.sender)[1]
            if "@" in addr:
                add("email", addr, "phish_report", 75, True, "Sender of an email an admin confirmed as phishing.")

    for t in (db.query(models.Takedown)
              .filter(models.Takedown.tenant_id == tenant.id, models.Takedown.status != "closed").all()):
        note = "Phishing site with a takedown request" + (" (now down)." if t.status == "down" else ".")
        add("domain", t.domain, "takedown", 90, True, note)
        if t.url:
            add("url", t.url, "takedown", 90, True, note)
    return out


def sync(db: Session, tenant: models.Tenant, now: datetime | None = None) -> dict:
    """Bring the stored indicators in line with collect(). Returns counts."""
    now = now or datetime.utcnow()
    now = now.replace(microsecond=now.microsecond // 1000 * 1000)  # STIX timestamps carry milliseconds
    want = collect(db, tenant, now)
    rows = {(r.kind, r.value): r for r in
            db.query(models.ThreatIndicator).filter(models.ThreatIndicator.tenant_id == tenant.id).all()}
    added = changed = revoked = 0
    for (kind, value), w in want.items():
        desc = " ".join(w["notes"])[:2000]
        sources = sorted(w["sources"])
        row = rows.get((kind, value))
        if row is None:
            db.add(models.ThreatIndicator(
                tenant_id=tenant.id, stix_id=stix_id(tenant.id, kind, value), kind=kind, value=value,
                sources=sources, confidence=w["confidence"], malicious=w["malicious"], description=desc,
                first_seen=now, last_seen=now, modified=now, revoked=False))
            added += 1
            continue
        row.last_seen = now
        if (row.revoked or row.confidence != w["confidence"] or row.malicious != w["malicious"]
                or row.description != desc or list(row.sources or []) != sources):
            row.revoked, row.confidence, row.malicious = False, w["confidence"], w["malicious"]
            row.description, row.sources, row.modified = desc, sources, now
            changed += 1
    for key, row in rows.items():
        if key not in want and not row.revoked:
            row.revoked, row.modified = True, now
            revoked += 1
    db.commit()
    return {"added": added, "changed": changed, "revoked": revoked}


# ------------------------------------------------------------------ STIX
def _quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


PATTERN = {"domain": "domain-name:value", "url": "url:value", "email": "email-addr:value"}
NAMES = {"domain": "Phishing domain", "url": "Phishing URL", "email": "Phishing sender"}


def identity(tenant: models.Tenant) -> dict:
    created = _stamp(tenant.created_at or datetime(2026, 1, 1))
    return {"type": "identity", "spec_version": "2.1", "id": identity_id(tenant.id), "created": created,
            "modified": created, "name": f"PhishLens ({tenant.name})"[:250], "identity_class": "organization"}


def to_stix(tenant: models.Tenant, row: models.ThreatIndicator) -> dict:
    obj = {
        "type": "indicator", "spec_version": "2.1", "id": row.stix_id,
        "created": _stamp(row.first_seen), "modified": _stamp(row.modified),
        "created_by_ref": identity_id(tenant.id),
        "name": f"{NAMES[row.kind]}: {row.value}"[:250],
        "description": row.description,
        "indicator_types": ["malicious-activity"] if row.malicious else ["anomalous-activity"],
        "pattern": f"[{PATTERN[row.kind]} = {_quote(row.value)}]",
        "pattern_type": "stix", "pattern_version": "2.1",
        "valid_from": _stamp(row.first_seen),
        "confidence": int(row.confidence),
        "labels": ["phishing"] + [f"source:{s}" for s in row.sources or []],
    }
    if row.revoked:
        obj["revoked"] = True
    return obj


def bundle(tenant: models.Tenant, rows: list[models.ThreatIndicator]) -> dict:
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()),
            "objects": [identity(tenant)] + [to_stix(tenant, r) for r in rows]}


# ------------------------------------------------------------------ plain lists
def csv_text(rows: list[models.ThreatIndicator]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "confidence", "malicious", "sources", "first_seen", "last_seen", "description"])
    for r in rows:
        w.writerow([r.kind, r.value, r.confidence, "yes" if r.malicious else "no", " ".join(r.sources or []),
                    _stamp(r.first_seen), _stamp(r.last_seen), r.description])
    return buf.getvalue()


def plain_list(rows: list[models.ThreatIndicator]) -> str:
    """One value per line, for firewall external block lists (EDL)."""
    return "".join(r.value + "\n" for r in rows)


def active(db: Session, tenant_id: str, kind: str | None = None, min_confidence: int = 0) -> list:
    q = db.query(models.ThreatIndicator).filter(models.ThreatIndicator.tenant_id == tenant_id,
                                                models.ThreatIndicator.revoked.is_(False),
                                                models.ThreatIndicator.confidence >= min_confidence)
    if kind:
        q = q.filter(models.ThreatIndicator.kind == kind)
    return q.order_by(models.ThreatIndicator.kind, models.ThreatIndicator.value).all()


def summary(db: Session, tenant_id: str) -> dict:
    rows = db.query(models.ThreatIndicator).filter(models.ThreatIndicator.tenant_id == tenant_id).all()
    live = [r for r in rows if not r.revoked]
    return {"total": len(live), "revoked": len(rows) - len(live),
            "by_kind": {k: sum(1 for r in live if r.kind == k) for k in KINDS},
            "malicious": sum(1 for r in live if r.malicious),
            "updated_at": _stamp(max(r.modified for r in rows)) if rows else None}
