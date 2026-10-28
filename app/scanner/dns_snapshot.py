"""DNS record snapshots for change monitoring.

Every monitored scan stores the records that matter for email security, so
the next rescan can say exactly what changed (and when, for the timeline).
"""
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from . import dns_checks

# Record label -> (owner name template, type, keep only TXT starting with).
# Groups decide which alert level reports a change.
RECORDS = {
    "SPF": ("{d}", "TXT", "v=spf1"),
    "DMARC": ("_dmarc.{d}", "TXT", "v=dmarc1"),
    "MTA-STS": ("_mta-sts.{d}", "TXT", "v=stsv1"),
    "TLS-RPT": ("_smtp._tls.{d}", "TXT", "v=tlsrptv1"),
    "BIMI": ("default._bimi.{d}", "TXT", "v=bimi1"),
    "MX": ("{d}", "MX", None),
    "NS": ("{d}", "NS", None),
    "A": ("{d}", "A", None),
    "AAAA": ("{d}", "AAAA", None),
}
AUTH_RECORDS = ("SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT", "BIMI")


class SnapshotError(Exception):
    pass


def _lookup(name: str, rtype: str, prefix: str | None) -> list[str]:
    try:
        answers = dns_checks._resolver.resolve(name, rtype, lifetime=dns_checks.TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise SnapshotError(f"{rtype} {name}: {type(exc).__name__}") from exc
    if rtype == "TXT":
        values = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
        values = [v for v in values if not prefix or v.lower().replace(" ", "").startswith(prefix)]
    elif rtype == "MX":
        values = [f"{r.preference} {r.exchange.to_text(omit_final_dot=True).lower()}" for r in answers]
    else:
        values = [r.to_text().rstrip(".").lower() for r in answers]
    return sorted(values)


def snapshot(domain: str, dkim_selector: str | None = None) -> dict[str, list[str]] | None:
    """The domain's email-security records, or None when a lookup failed: a
    half-read snapshot would report records as removed when DNS was slow."""
    jobs = {label: (tpl.format(d=domain), rtype, prefix) for label, (tpl, rtype, prefix) in RECORDS.items()}
    if dkim_selector:
        jobs["DKIM"] = (f"{dkim_selector}._domainkey.{domain}", "TXT", None)
    try:
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {label: pool.submit(_lookup, *job) for label, job in jobs.items()}
            return {label: f.result() for label, f in futures.items()}
    except SnapshotError:
        return None


def diff(old: dict | None, new: dict | None) -> list[dict]:
    """Changes between two snapshots: [{record, old, new}]. Records missing
    from either side (older scans, unknown selector) are not compared."""
    if not old or not new:
        return []
    changes = []
    for label in new:
        if label not in old:
            continue
        if sorted(old[label]) != sorted(new[label]):
            changes.append({"record": label, "old": old[label], "new": new[label]})
    return changes


def describe(change: dict) -> str:
    old, new = change["old"], change["new"]
    if not old:
        return f"{change['record']} record added: {'; '.join(new)}"
    if not new:
        return f"{change['record']} record removed (was: {'; '.join(old)})"
    return f"{change['record']} record changed from {'; '.join(old)} to {'; '.join(new)}"
