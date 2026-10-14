"""Product recommendations: the free-scan-to-XSignOn funnel.

Rule: the scan gives away every DNS fix for free — that is the funnel's value.
What DNS can never fix is credential phishing of your people via lookalike
domains and fake login pages. When the scan finds gaps, we say both things
plainly and recommend XSignOn Corporation products for the part only
phishing-resistant MFA closes.

Accuracy boundaries (standing):
- FIDO2 phishing-resistance / no-replayable-credential-at-login: fine.
- Never claim BioPro alone stops replay of an already-stolen session/token.
- Never imply XSignOn would have prevented a specific incident.
- No prices: enterprise pricing is quote-based.
- Company voice: XSignOn Corporation.
"""
CONTACT = "info@xsignon.com · +1 469-897-9399"

# Checks whose failure means the domain can be spoofed or mail intercepted —
# the phishing surface the free fixes address, and the residual risk BioPro closes.
PHISHING_CHECKS = {"spf", "dmarc", "dkim", "mx", "mta-sts", "bimi"}

RECOMMENDATION = {
    "headline": "DNS fixes stop spoofing. They don't stop phishing.",
    "body": (
        "The records above stop attackers from sending email as YOUR domain — and they "
        "are free to publish. What they cannot stop is an attacker emailing your team "
        "from a lookalike domain and harvesting logins on a fake sign-in page. That is "
        "how most breaches begin, and no DNS record fixes it. "
        "XSignOn AUTH BioPro replaces passwords with hardware-bound FIDO2 credentials "
        "verified by on-device fingerprint: there is no password to steal, and a fake "
        "login page cannot complete the authentication. AMS provisions, monitors, and "
        "retires every key across your workforce — with the audit evidence regulated "
        "environments need."
    ),
    "products": [
        {"name": "AUTH BioPro",
         "blurb": "Phishing-resistant MFA: FIDO2 security key with on-device fingerprint."},
        {"name": "AMS",
         "blurb": "Authenticator lifecycle management: issuance to retirement, audit-ready."},
    ],
    "cta": {"label": "Get an enterprise quote", "href": "mailto:info@xsignon.com"},
    "contact": CONTACT,
}


def build(check_results: list[dict], score: int) -> list[dict]:
    """Return product recommendations for a scan.

    Triggered only when the scan actually found gaps (score < 90). A clean
    scan gets no pitch — the free value stays free.
    """
    if score >= 90:
        return []
    failed = [c["title"] for c in check_results
              if c["status"] in ("fail", "warn") and c.get("key") in PHISHING_CHECKS]
    if not failed and score < 90:
        # Gaps exist but outside the phishing surface (e.g. headers only):
        # still worth one honest line, no hard pitch.
        return [{
            "headline": "Your email authentication is solid. Your people are still the target.",
            "body": (
                "This domain's mail controls look good — but most breaches start with a "
                "stolen login, not a spoofed domain. XSignOn AUTH BioPro removes passwords "
                "entirely with hardware-bound FIDO2 credentials, so there is nothing to phish."
            ),
            "products": RECOMMENDATION["products"],
            "cta": RECOMMENDATION["cta"],
            "contact": CONTACT,
        }]
    rec = dict(RECOMMENDATION)
    rec["triggered_by"] = failed
    return [rec]


def attach(result: dict) -> dict:
    """Add recommendations to an engine result dict in place."""
    checks = result.get("checks", [])
    result["recommendations"] = build(checks, result.get("score", 0))
    return result
