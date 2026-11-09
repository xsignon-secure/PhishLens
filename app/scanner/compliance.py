"""Mailbox-provider requirements: what Gmail, Yahoo and Microsoft ask of
senders, checked against a scan.

Gmail (Feb 2024, permanent 550 rejections since Nov 2025), Yahoo (Feb 2024)
and Microsoft's consumer mailboxes (outlook.com, hotmail.com, live.com;
rejections since 5 May 2025) ask bulk senders (about 5,000+ messages a day)
for SPF, DKIM and DMARC, alignment, reverse DNS, TLS, one-click unsubscribe
and a low spam rate. DNS shows most of these; the rest are marked "manual"
so the list stays honest about what a scan can and can't see.

These are findings, not fixes, so they appear in the free report too.
"""

PASS, FAIL, WARN, MANUAL = "pass", "fail", "warn", "manual"


def _by_key(checks: list[dict]) -> dict:
    return {c.get("key"): c for c in checks or []}


def _dmarc_policy(c: dict | None) -> str | None:
    record = (c or {}).get("record") or ""
    for tag in record.split(";"):
        k, _, v = tag.strip().partition("=")
        if k.strip().lower() == "p":
            return v.strip().lower()
    return None


def _status(c: dict | None) -> str:
    if not c or c.get("errored"):
        return MANUAL
    return {"pass": PASS, "warn": WARN}.get(c.get("status"), FAIL)


def rules(checks: list[dict]) -> dict[str, dict]:
    """Each requirement once, with its status and the check it comes from."""
    k = _by_key(checks)
    dkim = k.get("dkim")
    bits = (dkim or {}).get("bits")
    dkim_status = _status(dkim)
    if dkim_status == PASS and bits and bits < 1024:
        dkim_status = FAIL
    policy = _dmarc_policy(k.get("dmarc"))
    dmarc_ok = PASS if policy in ("none", "quarantine", "reject") else (MANUAL if not k.get("dmarc") else FAIL)
    spf = _status(k.get("spf"))
    return {
        "spf": {"label": "SPF record published and valid", "status": PASS if spf == WARN else spf, "check": "spf"},
        "dkim": {"label": "DKIM signing (key of 1024 bits or more, 2048 recommended)",
                 "status": dkim_status, "check": "dkim"},
        "spf_or_dkim": {"label": "SPF or DKIM passes",
                        "status": PASS if PASS in (spf, dkim_status) or spf == WARN else
                        (MANUAL if MANUAL in (spf, dkim_status) else FAIL), "check": "spf"},
        "dmarc": {"label": "DMARC published (p=none or stronger)", "status": dmarc_ok, "check": "dmarc"},
        "ptr": {"label": "Sending servers have forward-confirmed reverse DNS (PTR)",
                "status": _status(k.get("ptr")), "check": "ptr"},
        "tls": {"label": "Mail servers accept TLS", "status": _status(k.get("smtp-tls")), "check": "smtp-tls"},
        "alignment": {"label": "The From domain aligns with SPF or DKIM (see your DMARC reports)",
                      "status": MANUAL, "check": None},
        "unsubscribe": {"label": "Marketing mail has one-click unsubscribe (RFC 8058), honoured within 2 days",
                        "status": MANUAL, "check": None},
        "spam_rate": {"label": "Spam complaint rate under 0.1% (never above 0.3%)", "status": MANUAL, "check": None},
    }


PROVIDERS = [
    {"key": "gmail", "name": "Gmail",
     "note": "All senders need SPF or DKIM, PTR and TLS; 5,000+ a day also need SPF and DKIM, DMARC, "
             "alignment and one-click unsubscribe. Failing mail is rejected (550) since November 2025.",
     "rules": ["spf_or_dkim", "spf", "dkim", "dmarc", "alignment", "ptr", "tls", "unsubscribe", "spam_rate"]},
    {"key": "yahoo", "name": "Yahoo / AOL",
     "note": "Bulk senders need SPF, DKIM, DMARC, one-click unsubscribe and a spam rate under 0.3%.",
     "rules": ["spf", "dkim", "dmarc", "alignment", "ptr", "unsubscribe", "spam_rate"]},
    {"key": "microsoft", "name": "Outlook.com / Hotmail",
     "note": "5,000+ a day need SPF, DKIM and DMARC (p=none or stronger) with alignment. "
             "Failing mail is rejected (550 5.7.515) since 5 May 2025.",
     "rules": ["spf", "dkim", "dmarc", "alignment", "ptr", "unsubscribe"]},
]


def build(checks: list[dict]) -> list[dict]:
    r = rules(checks)
    out = []
    for p in PROVIDERS:
        items = [{"key": key, **r[key]} for key in p["rules"]]
        statuses = {i["status"] for i in items}
        overall = FAIL if FAIL in statuses else (WARN if WARN in statuses else PASS)
        out.append({"key": p["key"], "name": p["name"], "note": p["note"], "status": overall,
                    "passed": sum(1 for i in items if i["status"] == PASS),
                    "checked": sum(1 for i in items if i["status"] != MANUAL),
                    "rules": items})
    return out


def attach(result: dict) -> dict:
    result["compliance"] = build(result.get("checks") or [])
    return result
