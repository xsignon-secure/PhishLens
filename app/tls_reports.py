"""SMTP TLS reports (TLS-RPT, RFC 8460).

Sending servers that honour a domain's `_smtp._tls` record email a daily JSON
report (usually gzipped) saying how many TLS sessions to the domain's MX hosts
succeeded and why the others failed: expired or mismatched certificates, an
MTA-STS policy that couldn't be fetched, missing STARTTLS, DANE mismatches.
"""
import gzip
import io
import json
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError

from . import models

MAX_COMPRESSED = 5 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024

# RFC 8460 §4.3 result types, with what to do about each.
ADVICE = {
    "starttls-not-supported": "The MX host doesn't offer STARTTLS: turn it on at your mail server or provider.",
    "certificate-host-mismatch": "The MX certificate doesn't cover the MX hostname: reissue it with that name.",
    "certificate-expired": "An MX certificate has expired: renew it (and automate renewal).",
    "certificate-not-trusted": "An MX certificate isn't signed by a public CA: replace it with a publicly trusted one.",
    "validation-failure": "Certificate validation failed for another reason: check the full chain is served.",
    "tlsa-invalid": "A DANE TLSA record is malformed: republish it.",
    "dnssec-invalid": "DNSSEC validation failed for the MX or TLSA records: check your DNSSEC signing.",
    "dane-required": "DANE was required but no usable TLSA record was found.",
    "sts-policy-fetch-error": "Senders couldn't fetch your MTA-STS policy: check https://mta-sts.<domain>/.well-known/mta-sts.txt.",
    "sts-policy-invalid": "Your MTA-STS policy file is invalid: check its format and MX patterns.",
    "sts-webpki-invalid": "The certificate on mta-sts.<domain> isn't valid: fix it so senders can fetch the policy.",
}


class TlsReportError(ValueError):
    pass


def _dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def parse(blob: bytes) -> dict:
    if len(blob) > MAX_COMPRESSED:
        raise TlsReportError("File is too large (5 MB max)")
    if blob[:2] == b"\x1f\x8b":
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(blob)).read(MAX_JSON + 1)
        except (OSError, EOFError) as exc:
            raise TlsReportError("Could not decompress the .gz file") from exc
        if len(data) > MAX_JSON:
            raise TlsReportError("Report is too large once decompressed")
        blob = data
    try:
        doc = json.loads(blob)
    except (ValueError, UnicodeDecodeError) as exc:
        raise TlsReportError("Not a TLS-RPT JSON report") from exc
    if not isinstance(doc, dict) or "policies" not in doc:
        raise TlsReportError("Not a TLS-RPT report (no policies)")
    policies, domains = [], set()
    for pol in (doc.get("policies") or [])[:500]:
        p = pol.get("policy") or {}
        s = pol.get("summary") or {}
        domain = str(p.get("policy-domain") or "").lower().rstrip(".")
        if domain:
            domains.add(domain)
        failures = [{"result_type": str(f.get("result-type", "unknown"))[:60],
                     "sending_ip": str(f.get("sending-mta-ip", ""))[:64],
                     "mx": str(f.get("receiving-mx-hostname", ""))[:253],
                     "count": int(f.get("failed-session-count") or 0),
                     "reason": str(f.get("failure-reason-code", ""))[:200]}
                    for f in (pol.get("failure-details") or [])[:200]]
        policies.append({"type": str(p.get("policy-type", "no-policy-found"))[:30], "domain": domain,
                         "mx": [str(m)[:253] for m in (p.get("mx-host") or [])][:20],
                         "success": int(s.get("total-successful-session-count") or 0),
                         "failure": int(s.get("total-failure-session-count") or 0),
                         "failures": failures})
    if len(domains) != 1:
        raise TlsReportError("Report must cover exactly one domain")
    rng = doc.get("date-range") or {}
    return {"org_name": str(doc.get("organization-name") or "unknown")[:200],
            "report_id": str(doc.get("report-id") or "")[:200],
            "domain": domains.pop(), "date_begin": _dt(rng.get("start-datetime")),
            "date_end": _dt(rng.get("end-datetime")), "policies": policies}


def store(db, tenant_id: str, parsed: dict) -> tuple[models.TlsReport, bool]:
    report_id = parsed["report_id"] or f"{parsed['domain']}-{parsed['date_begin']}"
    existing = (db.query(models.TlsReport)
                .filter(models.TlsReport.tenant_id == tenant_id, models.TlsReport.org_name == parsed["org_name"],
                        models.TlsReport.report_id == report_id).first())
    if existing:
        return existing, False
    row = models.TlsReport(
        tenant_id=tenant_id, domain=parsed["domain"], org_name=parsed["org_name"], report_id=report_id,
        date_begin=parsed["date_begin"], date_end=parsed["date_end"], policies=parsed["policies"],
        success_count=sum(p["success"] for p in parsed["policies"]),
        failure_count=sum(p["failure"] for p in parsed["policies"]))
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return store(db, tenant_id, parsed)
    db.refresh(row)
    return row, True


def summarize(reports: list, domain: str, days: int) -> dict:
    success = sum(r.success_count for r in reports)
    failure = sum(r.failure_count for r in reports)
    by_type: dict[str, dict] = defaultdict(lambda: {"sessions": 0, "mx": set(), "reporters": set()})
    policy_types = set()
    for r in reports:
        for p in r.policies or []:
            policy_types.add(p["type"])
            for f in p["failures"]:
                t = by_type[f["result_type"]]
                t["sessions"] += f["count"]
                if f["mx"]:
                    t["mx"].add(f["mx"])
                t["reporters"].add(r.org_name)
    failures = sorted(
        ({"result_type": k, "sessions": v["sessions"], "mx": sorted(v["mx"])[:5],
          "reporters": sorted(v["reporters"])[:5],
          "fix": ADVICE.get(k, "See RFC 8460 §4.3 for this result type.").replace("<domain>", domain)}
         for k, v in by_type.items()), key=lambda x: -x["sessions"])
    total = success + failure
    return {"domain": domain, "days": days, "reports": len(reports), "successful_sessions": success,
            "failed_sessions": failure,
            "success_rate": round(100 * success / total, 1) if total else None,
            "policy_types": sorted(policy_types), "failures": failures}


def default_window(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)
