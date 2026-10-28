"""Observations: one row per failing or warning check (Risk, Severity,
Impact, Fix). Mirrors observationsTable() in app.js, for the PDF report."""

IMPACT = {
    "spf": "Receivers cannot tell which servers may send your mail, so forged mail is easier to deliver.",
    "dmarc": "Mail that fails authentication can still reach inboxes: attackers can send as your domain.",
    "dkim": "Your mail is not signed, so receivers cannot prove it came from you or was not changed.",
    "mta-sts": "Mail sent to you can be downgraded to unencrypted SMTP by an attacker in the middle.",
    "tls-rpt": "You will not hear about failed or downgraded TLS deliveries to your mail servers.",
    "bimi": "Your logo is not shown next to your mail in supporting inboxes.",
    "caa": "Any certificate authority can issue certificates for your domain.",
    "mx": "Mail for this domain may not be delivered.",
    "smtp-tls": "Mail to your servers may travel unencrypted.",
    "dnssec": "DNS answers for your domain can be spoofed, for example with cache poisoning.",
    "dnsbl": "Mail from your domain or servers is likely to be rejected or marked as spam.",
    "tls-cert": "Visitors may see certificate warnings, or the site may stop working when it expires.",
    "sec-headers": "Your website is easier to attack with clickjacking and content injection.",
}
LOW_SEVERITY = {"bimi", "caa", "ipv6", "sec-headers", "rpki", "ptr", "dane", "tls-rpt"}
RANK = {"High": 0, "Medium": 1, "Low": 2}


def severity(check: dict) -> str:
    if check.get("status") == "fail":
        return "High"
    return "Low" if check.get("key") in LOW_SEVERITY else "Medium"


def build(checks: list[dict]) -> list[dict]:
    rows = [{
        "risk": c.get("title", ""),
        "issue": (c.get("issues") or [""])[0],
        "severity": severity(c),
        "impact": IMPACT.get(c.get("key"), ""),
        "fix": (c.get("fixes") or [""])[0],
    } for c in checks if c.get("status") in ("fail", "warn")]
    return sorted(rows, key=lambda r: RANK[r["severity"]])
