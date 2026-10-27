"""DMARC aggregate (RUA) report ingestion and analysis.

Mailbox providers (Google, Microsoft, Yahoo, ...) send a daily XML report to
the address in a domain's DMARC `rua=` tag, listing every IP that sent mail as
that domain and whether it passed SPF / DKIM / DMARC. This module parses those
reports (raw XML, .gz or .zip, as they arrive) and turns them into the
per-sender view every DMARC product is built around: who sends as you, who
passes, and whether it is safe to move to p=quarantine / p=reject.
"""
import gzip
import io
import ipaddress
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from xml.etree import ElementTree as ET

MAX_COMPRESSED = 10 * 1024 * 1024
MAX_XML = 50 * 1024 * 1024  # decompressed; real reports are KBs to a few MB
MAX_RECORDS = 50_000


class ReportError(ValueError):
    pass


def _read_limited(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ReportError("Report is too large once decompressed")
    return data


def extract_xml(blob: bytes) -> bytes:
    """Return the XML document from a raw, gzip or zip report."""
    if len(blob) > MAX_COMPRESSED:
        raise ReportError("File is too large (10 MB max)")
    if blob[:2] == b"\x1f\x8b":
        try:
            return _read_limited(gzip.GzipFile(fileobj=io.BytesIO(blob)), MAX_XML)
        except (OSError, EOFError) as exc:
            raise ReportError("Could not decompress the .gz file") from exc
    if blob[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not names:
                    raise ReportError("The .zip file contains no XML report")
                with zf.open(names[0]) as fh:
                    return _read_limited(fh, MAX_XML)
        except zipfile.BadZipFile as exc:
            raise ReportError("Could not open the .zip file") from exc
    return blob


def _text(el, path: str, default: str = "") -> str:
    found = el.find(path) if el is not None else None
    return (found.text or "").strip() if found is not None and found.text else default


def _int(el, path: str, default: int = 0) -> int:
    try:
        return int(_text(el, path, str(default)))
    except ValueError:
        return default


def _strip_ns(root):
    # Some reporters namespace the document (DMARC 2.0 drafts); paths below
    # are written without namespaces.
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse(blob: bytes) -> dict:
    """Parse one aggregate report into a plain dict."""
    xml = extract_xml(blob)
    head = xml[:4096].lower()
    # Reports never use DTDs; refusing them rules out entity-expansion tricks.
    if b"<!doctype" in head or b"<!entity" in xml.lower():
        raise ReportError("Report contains a DTD, which DMARC reports never use")
    try:
        root = _strip_ns(ET.fromstring(xml))
    except ET.ParseError as exc:
        raise ReportError("Not a valid XML DMARC report") from exc
    if root.tag != "feedback":
        raise ReportError("Not a DMARC aggregate report (no <feedback> root)")

    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    domain = _text(pol, "domain").lower().rstrip(".")
    if not domain:
        raise ReportError("Report has no published-policy domain")
    begin, end = _int(meta, "date_range/begin"), _int(meta, "date_range/end")

    records = []
    for rec in root.findall("record"):
        if len(records) >= MAX_RECORDS:
            break
        row = rec.find("row")
        ip = _text(row, "source_ip")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        auth = rec.find("auth_results")
        dkim_auth = [{"domain": _text(d, "domain").lower(), "selector": _text(d, "selector"),
                      "result": _text(d, "result").lower()}
                     for d in (auth.findall("dkim") if auth is not None else [])]
        spf_auth = [{"domain": _text(s, "domain").lower(), "result": _text(s, "result").lower()}
                    for s in (auth.findall("spf") if auth is not None else [])]
        records.append({
            "source_ip": ip,
            "count": max(_int(row, "count"), 0),
            "disposition": _text(row, "policy_evaluated/disposition", "none").lower(),
            "dkim": _text(row, "policy_evaluated/dkim", "fail").lower(),
            "spf": _text(row, "policy_evaluated/spf", "fail").lower(),
            "header_from": _text(rec, "identifiers/header_from", domain).lower(),
            "envelope_from": _text(rec, "identifiers/envelope_from").lower(),
            "dkim_auth": dkim_auth[:5],
            "spf_auth": spf_auth[:5],
        })

    return {
        "org_name": _text(meta, "org_name", "unknown")[:200],
        "report_id": _text(meta, "report_id", "")[:200],
        "email": _text(meta, "email")[:320],
        "date_begin": datetime.utcfromtimestamp(begin) if begin else None,
        "date_end": datetime.utcfromtimestamp(end) if end else None,
        "domain": domain,
        "policy": {
            "p": _text(pol, "p", "none").lower(),
            "sp": _text(pol, "sp").lower() or None,
            "pct": _int(pol, "pct", 100),  # legacy RFC 7489 reports
            "np": _text(pol, "np").lower() or None,
            "testing": _text(pol, "testing").lower() in ("y", "true", "1"),  # RFC 9990
            "adkim": _text(pol, "adkim", "r").lower(),
            "aspf": _text(pol, "aspf", "r").lower(),
        },
        "records": records,
    }


# Sending services, recognised from the DKIM signing domain or SPF domain in
# the report. Lets the summary say "Google Workspace" instead of an IP.
_KNOWN_SENDERS = [
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"), ("protection.outlook.com", "Microsoft 365"),
    ("onmicrosoft.com", "Microsoft 365"),
    ("amazonses.com", "Amazon SES"), ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"), ("mailgun.net", "Mailgun"), ("mcsv.net", "Mailchimp"),
    ("mailchimpapp.net", "Mailchimp"), ("mandrillapp.com", "Mailchimp Transactional"),
    ("sparkpostmail.com", "SparkPost"), ("postmarkapp.com", "Postmark"),
    ("hubspotemail.net", "HubSpot"), ("hubspot.com", "HubSpot"),
    ("salesforce.com", "Salesforce"), ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("zendesk.com", "Zendesk"), ("freshdesk.com", "Freshdesk"),
    ("zoho.com", "Zoho Mail"), ("zohomail.com", "Zoho Mail"),
    ("brevo.com", "Brevo"), ("sendinblue.com", "Brevo"), ("klaviyomail.com", "Klaviyo"),
    ("constantcontact.com", "Constant Contact"), ("intercom-mail.com", "Intercom"),
    ("mktomail.com", "Marketo"), ("yahoo.com", "Yahoo"), ("icloud.com", "iCloud Mail"),
]


def _org_domain(name: str) -> str:
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name



def identify_sender(record: dict, own_domain: str) -> str:
    domains = [d["domain"] for d in record.get("dkim_auth", []) if d.get("domain")]
    domains += [s["domain"] for s in record.get("spf_auth", []) if s.get("domain")]
    if record.get("envelope_from"):
        domains.append(record["envelope_from"])
    for d in domains:
        for suffix, label in _KNOWN_SENDERS:
            if d == suffix or d.endswith("." + suffix):
                return label
    for d in domains:
        if d and _org_domain(d) != _org_domain(own_domain):
            return _org_domain(d)
    if domains:
        return f"{own_domain} (own servers)"
    return "Unknown sender"


def summarize(reports: list, domain: str, days: int) -> dict:
    """Roll stored reports up into per-sender results and a policy verdict.

    `reports` are DmarcReport rows (or anything with .records / .policy /
    .date_begin / .date_end / .org_name)."""
    senders: dict[str, dict] = {}
    total = passed = 0
    by_day: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    reporters = set()
    first = last = None
    policy = None
    for rep in reports:
        reporters.add(rep.org_name)
        policy = policy or rep.policy
        if rep.date_begin and (first is None or rep.date_begin < first):
            first = rep.date_begin
        if rep.date_end and (last is None or rep.date_end > last):
            last = rep.date_end
        day = (rep.date_begin or rep.created_at).strftime("%Y-%m-%d")
        for rec in rep.records or []:
            n = rec.get("count", 0)
            ok = rec.get("dkim") == "pass" or rec.get("spf") == "pass"
            total += n
            passed += n if ok else 0
            by_day[day][0] += n
            by_day[day][1] += n if ok else 0
            name = identify_sender(rec, domain)
            s = senders.setdefault(name, {"sender": name, "messages": 0, "passed": 0,
                                          "dkim_aligned": 0, "spf_aligned": 0,
                                          "ips": set(), "quarantined": 0, "rejected": 0})
            s["messages"] += n
            s["passed"] += n if ok else 0
            s["dkim_aligned"] += n if rec.get("dkim") == "pass" else 0
            s["spf_aligned"] += n if rec.get("spf") == "pass" else 0
            s["ips"].add(rec.get("source_ip"))
            if rec.get("disposition") == "quarantine":
                s["quarantined"] += n
            elif rec.get("disposition") == "reject":
                s["rejected"] += n

    rows = []
    for s in senders.values():
        rate = round(100 * s["passed"] / s["messages"], 1) if s["messages"] else 0.0
        if rate >= 95:
            status = "pass"
        elif s["passed"] == 0:
            status = "fail"
        else:
            status = "warn"
        fix = None
        if status != "pass":
            if s["dkim_aligned"] == 0:
                fix = (f"If {s['sender']} is a service you use, turn on DKIM signing for "
                       f"{domain} in its settings (it gives you a CNAME/TXT record to publish). "
                       "If you don't recognise it, this is spoofing: enforcement will block it.")
            else:
                fix = (f"Some {s['sender']} mail is unsigned. Make sure every stream "
                       f"(marketing, transactional, support) signs with DKIM for {domain}.")
        rows.append({
            "sender": s["sender"], "messages": s["messages"], "pass_rate": rate,
            "dkim_aligned": s["dkim_aligned"], "spf_aligned": s["spf_aligned"],
            "ip_count": len(s["ips"]), "sample_ips": sorted(i for i in s["ips"] if i)[:5],
            "quarantined": s["quarantined"], "rejected": s["rejected"],
            "status": status, "fix": fix,
        })
    rows.sort(key=lambda r: -r["messages"])

    pass_rate = round(100 * passed / total, 1) if total else None
    span_days = (last - first).days + 1 if first and last else 0
    verdict = _verdict(policy, pass_rate, span_days, rows, domain)
    return {
        "domain": domain, "days": days, "reports": len(reports),
        "reporters": sorted(r for r in reporters if r),
        "messages": total, "passed": passed, "pass_rate": pass_rate,
        "first": first.isoformat() + "Z" if first else None,
        "last": last.isoformat() + "Z" if last else None,
        "policy": policy, "senders": rows,
        "daily": [{"day": d, "messages": v[0], "passed": v[1]} for d, v in sorted(by_day.items())],
        "verdict": verdict,
    }


def _verdict(policy, pass_rate, span_days, rows, domain) -> dict:
    p = (policy or {}).get("p", "none")
    if pass_rate is None:
        return {"level": "info", "message": "No report data yet for this period."}
    failing_legit = [r for r in rows if r["status"] != "pass" and r["messages"] >= 10
                     and not r["sender"].startswith("Unknown")]
    if p == "reject":
        return {"level": "pass", "message": "You're at p=reject: spoofed mail is blocked. "
                "Keep watching for new senders that fail."}
    if span_days < 14:
        return {"level": "info", "message": f"Only {span_days} day(s) of data. Collect at least "
                "two weeks (monthly senders like invoicing tools need longer) before tightening policy."}
    if pass_rate >= 98 and not failing_legit:
        nxt = "quarantine" if p == "none" else "reject"
        return {"level": "pass", "message": f"{pass_rate}% of your mail passes. It looks safe to move "
                f"to p={nxt}.",
                "record": f"_dmarc.{domain}  TXT  \"v=DMARC1; p={nxt}; rua=mailto:<your report address>\""
                + ("" if nxt == "quarantine" else "  (optionally add np=reject)")}
    names = ", ".join(r["sender"] for r in failing_legit[:3]) or "some senders"
    return {"level": "warn", "message": f"{pass_rate}% of your mail passes. Fix {names} before "
            f"moving beyond p={p}, or legitimate mail will be blocked."}


def default_window(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)
