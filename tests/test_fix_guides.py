"""Step-by-step fix cards: the scanner's findings turned into exact record fields."""
from app import pdf_report
from app.scanner import engine, guides, scoring

D = "acme.example"
GOOGLE_MX = ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]


def _check(key, status="fail", **kw):
    return {"key": key, "title": key.upper(), "status": status, "score": kw.pop("score", 0),
            "max_score": kw.pop("max_score", 10), "details": kw.pop("details", ""),
            "issues": kw.pop("issues", ["x"]), "fixes": kw.pop("fixes", ["old one-line fix"]), **kw}


def _build(check, mx=None):
    return guides.build(check, D, {"mx_hosts": mx or []})


def test_missing_dmarc_gives_record_fields_not_a_sentence():
    g = _build(_check("dmarc"))
    rec = g["records"][0]
    assert rec == {"action": "add", "type": "TXT", "host": "_dmarc", "fqdn": f"_dmarc.{D}",
                   "value": f"v=DMARC1; p=none; rua=mailto:dmarc@{D}", "note": rec["note"]}
    assert g["problem"] and g["why"] and g["warning"] and g["minutes"]


def test_dmarc_steps_up_one_policy_level_and_drops_obsolete_tags():
    g = _build(_check("dmarc", "warn", record="v=DMARC1; p=none; pct=50; rf=afrf"))
    rec = g["records"][0]
    assert rec["action"] == "replace" and rec["current"] == "v=DMARC1; p=none; pct=50; rf=afrf"
    assert rec["value"] == f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{D}; t=y"
    assert "check your dmarc reports" in g["warning"].lower()
    g = _build(_check("dmarc", "warn", record="v=DMARC1; p=quarantine; rua=mailto:a@b.c; sp=none"))
    assert g["records"][0]["value"] == "v=DMARC1; p=reject; rua=mailto:a@b.c"
    g = _build(_check("dmarc", "warn", record="v=DMARC1; p=reject; rua=mailto:a@b.c; t=y"))
    assert g["records"][0]["value"] == "v=DMARC1; p=reject; rua=mailto:a@b.c"


def test_spf_record_follows_the_mail_provider():
    assert _build(_check("spf"), GOOGLE_MX)["records"][0]["value"] == "v=spf1 include:_spf.google.com ~all"
    assert _build(_check("spf"), ["x.mail.protection.outlook.com"])["records"][0]["value"] == \
        "v=spf1 include:spf.protection.outlook.com ~all"
    assert _build(_check("spf"), ["mail.acme.example"])["records"][0]["value"] == "v=spf1 mx ~all"
    assert _build(_check("spf"), [])["records"][0]["value"] == "v=spf1 -all"


def test_spf_changes_show_the_old_and_new_value():
    g = _build(_check("spf", "warn", record="v=spf1 include:_spf.google.com ~all", issues=["SPF ends in ~all"]))
    rec = g["records"][0]
    assert (rec["action"], rec["host"], rec["current"], rec["value"]) == (
        "replace", "@", "v=spf1 include:_spf.google.com ~all", "v=spf1 include:_spf.google.com -all")
    g = _build(_check("spf", record="v=spf1 ip4:0.0.0.0/0 include:x.com -all",
                      issues=["SPF authorizes 0.0.0.0/0: the entire internet"]))
    assert g["records"][0]["value"] == "v=spf1 include:x.com -all"
    g = _build(_check("spf", record="v=spf1 a ptr ~all", issues=["SPF ends in ~all", "ptr"]))
    assert g["records"][0]["value"] == "v=spf1 a -all"
    g = _build(_check("spf", records=["v=spf1 include:a.com ~all", "v=spf1 include:b.com -all"]))
    assert g["records"][0]["value"] == "v=spf1 include:a.com include:b.com -all"
    g = _build(_check("spf", record="v=spf1 " + " ".join(f"include:s{i}.com" for i in range(12)) + " -all",
                      issues=["SPF causes 12 DNS lookups (limit is 10)"]))
    assert not g["records"] and any("host your SPF" in s for s in g["steps"])


def test_mta_sts_card_includes_the_policy_file_with_real_mx_hosts():
    g = _build(_check("mta-sts", details="No MTA-STS record."), GOOGLE_MX)
    assert g["records"][0]["host"] == "_mta-sts" and g["records"][0]["value"].startswith("v=STSv1; id=")
    assert g["file"]["url"] == f"https://mta-sts.{D}/.well-known/mta-sts.txt"
    assert "mode: testing" in g["file"]["content"] and "mx: alt1.aspmx.l.google.com" in g["file"]["content"]


def test_dkim_points_to_the_mail_provider_for_the_value():
    g = _build(_check("dkim"), GOOGLE_MX)
    assert g["records"][0]["value_from_provider"] and g["records"][0]["host"] == "google._domainkey"
    assert "Google Admin console" in g["steps"][0]


def test_steps_only_and_unknown_checks_still_get_a_card():
    assert _build(_check("dnssec", "warn"))["steps"]
    g = _build(_check("brand-new-check", "warn", issues=["Something odd"], fixes=["Do the thing."]))
    assert g["headline"] == "Something odd" and g["steps"] == ["Do the thing."]
    assert _build(_check("spf", "pass")) is None


def test_attach_links_guides_to_the_action_plan():
    checks = [_check("dmarc", max_score=20), _check("mx", "pass", score=5, max_score=5, hosts=GOOGLE_MX),
              _check("spf", "fail", max_score=15)]
    result = {"domain": D, "checks": checks, "action_plan": scoring.action_plan(checks)}
    guides.attach(result)
    assert [p["key"] for p in result["action_plan"]] == ["dmarc", "spf"]
    assert result["action_plan"][1]["guide"]["records"][0]["value"] == "v=spf1 include:_spf.google.com ~all"
    assert "guide" not in checks[1]


def test_old_scans_get_guides_when_read_without_changing_the_stored_copy():
    stored = {"domain": D, "checks": [_check("dmarc")], "action_plan": []}
    out = engine.with_guides(stored)
    assert out["checks"][0]["guide"]["records"] and "guide" not in stored["checks"][0]


def test_nameservers_identify_the_dns_host():
    assert guides.match_nameservers(["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."])["key"] == "cloudflare"
    assert guides.match_nameservers(["ns05.domaincontrol.com"])["label"] == "GoDaddy"
    assert guides.match_nameservers(["ns-1.awsdns-01.org"])["key"] == "route53"
    assert guides.match_nameservers(["ns1.example-dns.net"]) == {
        "key": "other", "label": None, "nameservers": ["ns1.example-dns.net"]}


def test_pdf_prints_the_fix_cards():
    checks = [_check("dmarc", max_score=20), _check("dnssec", "warn", max_score=5)]
    result = {"domain": D, "score": 40, "grade": "F", "checks": checks,
              "action_plan": scoring.action_plan(checks)[:1]}
    guides.attach(result)
    pdf = pdf_report.render({"result": result})
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000
