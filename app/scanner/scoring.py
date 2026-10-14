"""Scoring: weighted 0-100 aggregation + letter grade + prioritized action plan."""
from concurrent.futures import ThreadPoolExecutor

from . import dns_checks, web_checks

# (check_fn, applies_to) — web checks run against the domain's web presence
EMAIL_CHECKS = [
    dns_checks.check_spf,
    dns_checks.check_dmarc,
    dns_checks.check_dkim,
    dns_checks.check_mx,
    dns_checks.check_smtp_tls,
    dns_checks.check_mta_sts,
    dns_checks.check_tls_rpt,
    dns_checks.check_bimi,
    dns_checks.check_caa,
    dns_checks.check_dnsbl,
    dns_checks.check_dnssec,
]
WEB_CHECKS = [
    web_checks.check_tls_cert,
    web_checks.check_security_headers,
]

def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _run_check(fn, domain: str) -> dict:
    try:
        return fn(domain)
    except Exception as e:  # a check must never kill the scan
        name = getattr(fn, "__name__", "check")
        reason = ("DNS servers did not answer; try again shortly"
                  if isinstance(e, dns_checks.DnsLookupError) else type(e).__name__)
        # max_score 0 keeps an unanswerable check out of the score instead of
        # counting it as failed; "errored" marks the scan as incomplete.
        return {
            "key": name, "title": name.removeprefix("check_").replace("_", " ").upper(),
            "status": "warn", "score": 0, "max_score": 0, "errored": True,
            "details": f"Check could not complete: {reason}.",
            "issues": [], "fixes": [],
        }


def run_all_checks(domain: str) -> list[dict]:
    """Run every check concurrently; results keep the registry order.

    Checks are independent network probes (DNS, SMTP, HTTPS), so running them
    in parallel bounds scan time by the slowest check instead of the sum."""
    checks = list(EMAIL_CHECKS) + list(WEB_CHECKS)
    with ThreadPoolExecutor(max_workers=len(checks) or 1) as pool:
        return list(pool.map(lambda fn: _run_check(fn, domain), checks))


def score_results(results: list[dict]) -> tuple[int, str]:
    earned = sum(r["score"] for r in results)
    possible = sum(r["max_score"] for r in results)
    score = round(100 * earned / possible) if possible else 0
    return score, grade_for(score)


def action_plan(results: list[dict], limit: int = 5) -> list[dict]:
    """Highest-impact fixes first: failed checks with the most recoverable points."""
    cands = []
    for r in results:
        recoverable = r["max_score"] - r["score"]
        if r["status"] != "pass" and recoverable > 0 and r["fixes"]:
            cands.append((recoverable, r))
    cands.sort(key=lambda x: -x[0])
    return [
        {"check": r["title"], "fix": r["fixes"][0], "points": rec}
        for rec, r in cands[:limit]
    ]
