"""Route 53 / GoDaddy one-click fixes, phishing URL checker, translations."""
import glob
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from app import dns_providers

NS = "https://route53.amazonaws.com/doc/2013-04-01/"


# ------------------------------------------------------------------ DNS providers
def test_sigv4_matches_aws_test_vector():
    h = dns_providers.sigv4_headers(
        "GET", "https://example.amazonaws.com/", b"", "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", service="service",
        now=datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc))
    assert h["Authorization"].endswith("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


def test_godaddy_rrset_upsert_keeps_unrelated_txt():
    rrsets = {("_dmarc", "TXT"): ["google-site-verification=1"]}
    seen = []

    def handler(req: httpx.Request):
        seen.append(req.headers["authorization"])
        path = req.url.path
        if path in ("/v1/domains", "/v1/domains/x.com"):
            return httpx.Response(200, json=[] if path == "/v1/domains" else {"domain": "x.com"})
        if path == "/v1/domains/_dmarc.x.com":
            return httpx.Response(404, json={"message": "Not found"})
        _, rtype, sub = path.rsplit("/", 2)
        if req.method == "PUT":
            rrsets[(sub, rtype)] = [r["data"] for r in json.loads(req.content)]
            return httpx.Response(200)
        return httpx.Response(200, json=[{"data": v} for v in rrsets.get((sub, rtype), [])])

    g = dns_providers.client("godaddy", "key123456789:secret123456", httpx.MockTransport(handler))
    assert g.verify()
    zone, _ = g.zone_for("_dmarc.x.com")
    assert zone == "x.com"
    assert g.upsert(zone, "_dmarc.x.com", "TXT", '"v=DMARC1; p=none"') == "created"
    assert rrsets[("_dmarc", "TXT")] == ["google-site-verification=1", "v=DMARC1; p=none"]
    assert g.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=none") == "unchanged"
    assert g.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=reject") == "updated"
    assert rrsets[("_dmarc", "TXT")][1] == "v=DMARC1; p=reject"
    assert seen[0] == "sso-key key123456789:secret123456"


def test_godaddy_403_explains_account_limit():
    g = dns_providers.client("godaddy", "k" * 12 + ":" + "s" * 12,
                             httpx.MockTransport(lambda r: httpx.Response(403, json={"code": "ACCESS_DENIED"})))
    try:
        g.verify()
    except dns_providers.DnsProviderError as exc:
        assert "10 or more domains" in str(exc)
    else:
        raise AssertionError("expected an error")


def test_route53_upsert_signs_requests_and_writes_xml():
    rrsets = {("_dmarc.x.com.", "TXT"): ['"google-site-verification=1"']}
    posts = []

    def handler(req: httpx.Request):
        assert req.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
        path, q = req.url.path, dict(req.url.params)
        if path == "/2013-04-01/hostedzone":
            return httpx.Response(200, content=f'<ListHostedZonesResponse xmlns="{NS}"/>')
        if path == "/2013-04-01/hostedzonesbyname":
            name = q["dnsname"]
            zones = f"<HostedZone><Id>/hostedzone/Z1</Id><Name>{name}.</Name></HostedZone>" if name == "x.com" else \
                "<HostedZone><Id>/hostedzone/Z9</Id><Name>zzz.com.</Name></HostedZone>"
            return httpx.Response(200, content=f'<ListHostedZonesByNameResponse xmlns="{NS}"><HostedZones>{zones}</HostedZones></ListHostedZonesByNameResponse>')
        if path == "/2013-04-01/hostedzone/Z1/rrset" and req.method == "GET":
            vals = rrsets.get((q["name"], q["type"]), [])
            body = "".join(f"<ResourceRecord><Value>{v}</Value></ResourceRecord>" for v in vals)
            rs = (f"<ResourceRecordSet><Name>{q['name']}</Name><Type>{q['type']}</Type>"
                  f"<ResourceRecords>{body}</ResourceRecords></ResourceRecordSet>") if vals else ""
            return httpx.Response(200, content=f'<ListResourceRecordSetsResponse xmlns="{NS}"><ResourceRecordSets>{rs}</ResourceRecordSets></ListResourceRecordSetsResponse>')
        if path == "/2013-04-01/hostedzone/Z1/rrset" and req.method == "POST":
            root = ET.fromstring(req.content)
            posts.append(root)
            rs = root.find(f".//{{{NS}}}ResourceRecordSet")
            key = (rs.findtext(f"{{{NS}}}Name"), rs.findtext(f"{{{NS}}}Type"))
            rrsets[key] = [v.text for v in rs.iter(f"{{{NS}}}Value")]
            return httpx.Response(200, content=f'<ChangeResourceRecordSetsResponse xmlns="{NS}"/>')
        return httpx.Response(404, content=f'<ErrorResponse xmlns="{NS}"><Error><Message>nope</Message></Error></ErrorResponse>')

    r = dns_providers.client("route53", "AKIAEXAMPLE:secretsecret", httpx.MockTransport(handler))
    assert r.verify()
    zone, name = r.zone_for("_dmarc.x.com")
    assert (zone, name) == ("Z1", "x.com")
    assert r.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=none") == "created"
    assert rrsets[("_dmarc.x.com.", "TXT")] == ['"google-site-verification=1"', '"v=DMARC1; p=none"']
    assert posts[-1].findtext(f".//{{{NS}}}Action") == "UPSERT"
    assert r.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=none") == "unchanged"


def test_route53_rejects_malformed_credential():
    try:
        dns_providers.client("route53", "no-colon-here-at-all-xx")
    except dns_providers.DnsProviderError as exc:
        assert "ACCESS_KEY_ID" in str(exc)
    else:
        raise AssertionError("expected an error")


def test_long_txt_is_split_into_255_byte_strings():
    v = "v=spf1 " + "include:a.example.com " * 20 + "-all"
    out = dns_providers.RRsetProvider._fmt("TXT", v)
    parts = re.findall(r'"([^"]*)"', out)
    assert "".join(parts) == v and all(len(p) <= 255 for p in parts) and len(parts) == 2


# ------------------------------------------------------------------ phishing URL checker
import pytest  # noqa: E402

from app import url_check  # noqa: E402


@pytest.fixture()
def offline(monkeypatch):
    monkeypatch.setattr(url_check, "blocklists", lambda d: [])
    monkeypatch.setattr(url_check, "resolves", lambda h: True)
    monkeypatch.setattr(url_check, "domain_age_days", lambda d: 4000)
    monkeypatch.setattr(url_check.reputation, "lookup", lambda d: None)


def test_url_checker_flags_brand_on_wrong_domain(offline):
    r = url_check.check("http://paypal.com.account-verify.xyz/signin")
    assert r["verdict"] == "likely phishing" and r["domain"] == "account-verify.xyz"
    assert any("paypal" in s["text"] for s in r["signals"])


def test_url_checker_leaves_real_sites_alone(offline):
    for url in ("https://login.microsoftonline.com/common/oauth2", "https://groups.google.com/",
                "https://github.com/startups"):
        assert url_check.check(url)["verdict"] == "no known threat", url


def test_url_checker_new_domain_and_blocklist(offline, monkeypatch):
    monkeypatch.setattr(url_check, "domain_age_days", lambda d: 3)
    assert url_check.check("https://paypal-help.com/login")["verdict"] == "likely phishing"
    monkeypatch.setattr(url_check, "blocklists", lambda d: ["dbl.spamhaus.org"])
    r = url_check.check("https://example.com/")
    assert r["verdict"] == "dangerous" and r["feeds"][0]["lists"] == ["dbl.spamhaus.org"]


def test_url_checker_ip_and_userinfo(offline):
    r = url_check.check("https://user@198.51.100.7:8443/office365/login")
    texts = " ".join(s["text"] for s in r["signals"])
    assert "raw IP" in texts and "'@'" in texts and "port" in texts
    assert r["verdict"] == "likely phishing"


def test_url_checker_endpoint(offline):
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.post("/api/tools/url", json={"url": "javascript:alert(1)"}).status_code == 400
    r = c.post("/api/tools/url", json={"url": "example.com"})
    assert r.status_code == 200 and r.json()["verdict"] == "no known threat"


def test_safe_browsing_feed_marks_dangerous(offline, monkeypatch):
    monkeypatch.setattr(url_check, "safe_browsing", lambda u: True)
    r = url_check.check("https://example.com/")
    assert r["verdict"] == "dangerous" and {"source": "Google Safe Browsing", "listed": True} in r["feeds"]


from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine as sa_engine  # noqa: E402
from app.main import app  # noqa: E402
from app import i18n  # noqa: E402


def _unescape(s):
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), s)


def _template_strings():
    """Every translatable string: _("...") in templates, _t('...') in page and app.js scripts."""
    keys = set()
    for f in glob.glob("app/templates/*.html") + ["app/static/app.js"]:
        src = open(f, encoding="utf-8").read()
        keys |= {_unescape(m) for m in re.findall(r'(?<![\w$])_\("((?:[^"\\]|\\.)*)"\)', src)}
        keys |= {_unescape(m) for m in re.findall(r"(?<![\w$])(?:_t|N_)\('((?:[^'\\]|\\.)*)'", src)}
    return keys


def test_every_catalog_covers_every_template_string():
    keys = _template_strings()
    assert len(keys) > 300
    for lang in i18n.LANGS:
        if lang == "en":
            continue
        catalog = json.load(open(f"app/locales/{lang}.json", encoding="utf-8"))
        assert keys <= set(catalog), (lang, keys - set(catalog))
        assert not set(catalog) - keys, (lang, "stale entries", set(catalog) - keys)


def test_language_from_cookie_then_accept_language():
    Base.metadata.create_all(bind=sa_engine)
    c = TestClient(app)
    r = c.get("/", headers={"Accept-Language": "de-DE,de;q=0.9,en;q=0.8"})
    assert 'lang="de"' in r.text and "Meine Domain scannen" in r.text
    c.cookies.set("lang", "es")
    r = c.get("/tools", headers={"Accept-Language": "de"})
    assert 'lang="es"' in r.text and "¿Este enlace es phishing?" in r.text
    c.cookies.set("lang", "xx")
    r = c.get("/login", headers={"Accept-Language": "fr-CA,fr;q=0.9"})
    assert "Outils gratuits" in r.text
    c.cookies.clear()
    assert "Scan my domain" in c.get("/").text


def test_dashboard_scripts_get_the_catalog():
    Base.metadata.create_all(bind=sa_engine)
    c = TestClient(app)
    c.cookies.set("lang", "es")
    r = c.get("/dashboard")
    assert "window.I18N = {" in r.text and "Vigilar un dominio" in r.text
    assert '"Scan history": "Historial de escaneos"' in r.text
    c.cookies.set("lang", "en")
    assert "window.I18N = {}" in c.get("/dashboard").text
