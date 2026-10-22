"""Next-step advice for a scan: what DNS records can't fix.

The scan gives every DNS fix for free. What DNS can never fix is credential
phishing of your people through lookalike domains and fake sign-in pages, so
when a scan finds gaps we say so plainly and point to phishing-resistant MFA.
Vendor-neutral on purpose: no products, prices or sales contacts.
"""

# Checks whose failure means the domain can be spoofed or mail intercepted.
PHISHING_CHECKS = {"spf", "dmarc", "dkim", "mx", "mta-sts", "bimi"}

LEARN_MORE = {"label": "CISA guide to phishing-resistant MFA", "href": "https://www.cisa.gov/mfa"}

RECOMMENDATION = {
    "headline": "DNS fixes stop spoofing. They don't stop phishing.",
    "body": (
        "The records above stop attackers from sending email as YOUR domain, and they "
        "are free to publish. What they cannot stop is an attacker emailing your team "
        "from a lookalike domain and harvesting logins on a fake sign-in page. That is "
        "how most breaches begin, and no DNS record fixes it. "
        "Phishing-resistant MFA (passkeys or FIDO2 security keys) binds each sign-in to "
        "the real website, so a fake login page cannot complete the authentication."
    ),
    "products": [
        {"name": "Passkeys / FIDO2 security keys",
         "blurb": "Turn them on for email, SSO and admin accounts first; most identity providers support them."},
        {"name": "Watch lookalike domains",
         "blurb": "Monitor this domain in PhishLens to be alerted when lookalike domains are registered."},
    ],
    "cta": LEARN_MORE,
}


def build(check_results: list[dict], score: int) -> list[dict]:
    """Return next-step advice for a scan. A clean scan (score >= 90) gets none."""
    if score >= 90:
        return []
    failed = [c["title"] for c in check_results
              if c["status"] in ("fail", "warn") and c.get("key") in PHISHING_CHECKS]
    if not failed:
        # Gaps exist but outside the phishing surface (e.g. headers only).
        return [{
            "headline": "Your email authentication is solid. Your people are still the target.",
            "body": (
                "This domain's mail controls look good, but most breaches start with a "
                "stolen login, not a spoofed domain. Passkeys or FIDO2 security keys remove "
                "the password from sign-in, so there is nothing to phish."
            ),
            "products": RECOMMENDATION["products"],
            "cta": LEARN_MORE,
        }]
    rec = dict(RECOMMENDATION)
    rec["triggered_by"] = failed
    return [rec]


def attach(result: dict) -> dict:
    """Add recommendations to an engine result dict in place."""
    checks = result.get("checks", [])
    result["recommendations"] = build(checks, result.get("score", 0))
    return result
