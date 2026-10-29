"""Domain Connect, DKIM key health from reports, hosted TLS-RPT and BIMI,
and the BIMI logo checker."""
import base64
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import bimi, dmarc_reports, domain_connect
from app.config import settings
from app.scanner import dns_checks
from tests.test_fill_gaps import _auth, client, db, hosted_on  # noqa: F401  (fixtures)

LOGO = """<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
<title>X Co</title><rect width="100" height="100" fill="#123"/></svg>"""


# ------------------------------------------------------------------ BIMI logo check
def test_bimi_valid_logo_passes():
    r = bimi.check_svg(LOGO)
    assert r == {"ok": True, "errors": [], "warnings": [], "title": "X Co"}


def test_bimi_rejects_unsafe_and_non_tiny_ps():
    r = bimi.check_svg('<svg xmlns="http://www.w3.org/2000/svg" x="0" viewBox="0 0 200 100">'
                       '<script>alert(1)</script><image href="https://e.com/a.png"/>'
                       '<rect onclick="x()" width="1" height="1"/></svg>')
    text = " ".join(r["errors"])
    assert not r["ok"]
    for needle in ('version="1.2"', 'baseProfile="tiny-ps"', "<title>", "<script>", "<image>",
                   "onclick", "external files", "x= and y="):
        assert needle in text, needle
    assert "isn't square" in r["warnings"][0]
    assert bimi.check_svg('<!DOCTYPE svg [<!ENTITY a "b">]><svg/>')["errors"] == [
        "Remove the <!DOCTYPE> / <!ENTITY> declaration."]
    assert "Not valid XML" in bimi.check_svg("<svg")["errors"][0]
    assert "32 KB" in bimi.check_svg(LOGO.replace("<title>", "<title>" + "x" * 40000))["errors"][0]


def test_bimi_tool_endpoint(client):
    assert client.post("/api/tools/bimi-svg", json={"svg": LOGO}).json()["ok"] is True


# ------------------------------------------------------------------ hosted TLS-RPT and BIMI
def test_hosted_tls_rpt(client, hosted_on):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    r = client.put("/api/hosted/x.com/tls_rpt", json={"config": {}}, headers=h)
    assert r.status_code == 200, r.text
    rec = r.json()
    name, value = next(iter(rec["published"].items()))
    assert name.endswith("._smtp._tls.hosted.test")
    assert value == "v=TLSRPTv1; rua=mailto:dmarc@reports.hosted.test"
    assert rec["customer_records"][0]["name"] == "_smtp._tls.x.com"
    r = client.put("/api/hosted/x.com/tls_rpt", json={"config": {"rua": ["tls@x.com", "https://r.x.com/tls"]}}, headers=h)
    assert next(iter(r.json()["published"].values())) == "v=TLSRPTv1; rua=mailto:tls@x.com,https://r.x.com/tls"
    assert client.put("/api/hosted/x.com/tls_rpt", json={"config": {"rua": ["nope"]}}, headers=h).status_code == 400


def test_hosted_bimi_validates_serves_and_versions_logo(client, hosted_on, monkeypatch):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    put = lambda cfg: client.put("/api/hosted/x.com/bimi", json={"config": cfg}, headers=h)
    assert "HTTPS" in put({"svg": LOGO}).json()["detail"]  # APP_URL is http in tests
    monkeypatch.setattr(settings, "APP_URL", "https://pl.test")
    assert put({"svg": "<svg/>"}).status_code == 400
    assert put({"svg": LOGO, "certificate_url": "http://x/c.pem"}).status_code == 400
    rec = put({"svg": LOGO, "certificate_url": "https://ca.test/vmc.pem"}).json()
    value = next(iter(rec["published"].values()))
    assert value.startswith(f"v=BIMI1; l=https://pl.test/bimi/{rec['id']}/") and value.endswith("; a=https://ca.test/vmc.pem")
    assert rec["customer_records"][0]["name"] == "default._bimi.x.com"
    path = value.split("l=")[1].split(";")[0].replace("https://pl.test", "")
    logo = client.get(path)
    assert logo.status_code == 200 and logo.headers["content-type"] == "image/svg+xml"
    assert "sandbox" in logo.headers["content-security-policy"] and logo.text == LOGO
    # A new logo gets a new URL so inboxes refetch it; the same logo keeps it.
    same = next(iter(put({"svg": LOGO, "certificate_url": "https://ca.test/vmc.pem"}).json()["published"].values()))
    assert same == value
    new = next(iter(put({"svg": LOGO.replace("#123", "#456")}).json()["published"].values()))
    assert new != value and new.endswith("; a=")
    assert client.get("/bimi/nope/x.svg").status_code == 404


# ------------------------------------------------------------------ DKIM key health
def _report(days_ago, recs):
    when = datetime.utcnow() - timedelta(days=days_ago)
    return SimpleNamespace(date_begin=when, date_end=when, created_at=when, records=[
        {"count": n, "dkim": res, "spf": res, "source_ip": "192.0.2.1", "envelope_from": "",
         "dkim_auth": [{"domain": d, "selector": sel, "result": res}], "spf_auth": [{"domain": spf, "result": res}]}
        for n, res, d, sel, spf in recs])


def test_dkim_selectors_and_health():
    reports = [
        _report(2, [(900, "pass", "x.com", "google", "google.com"), (10, "fail", "x.com", "google", "google.com"),
                    (50, "pass", "mail.x.com", "s1", "sendgrid.net"), (99, "pass", "evil.com", "s1", "evil.com")]),
        _report(120, [(30, "pass", "x.com", "old", "mcsv.net")]),
    ]
    rows = dmarc_reports.dkim_selectors(reports, "x.com")
    assert [(r["domain"], r["selector"], r["messages"]) for r in rows] == [
        ("x.com", "google", 910), ("mail.x.com", "s1", 50), ("x.com", "old", 30)]  # evil.com left out
    assert rows[0]["service"] == "Google Workspace" and rows[0]["pass_rate"] == 98.9
    ok = dmarc_reports.dkim_health(rows[0], {"found": True, "bits": 2048, "type": "rsa"})
    assert ok["status"] == "pass" and ok["flags"] == []
    weak = dmarc_reports.dkim_health(rows[1], {"found": True, "bits": 1024, "type": "rsa"})
    assert weak["status"] == "warn" and "2048" in weak["flags"][0]["message"]
    stale = dmarc_reports.dkim_health(rows[2], {"found": True, "bits": 2048, "type": "rsa"})
    assert stale["status"] == "warn" and "Not used for 120 days" in stale["flags"][0]["message"]
    missing = dmarc_reports.dkim_health(rows[0], {"found": False})
    assert missing["status"] == "fail" and "No published key" in missing["flags"][0]["message"]


def test_dkim_endpoint(client, monkeypatch):
    import gzip
    h = _auth(client, "o@x.com")
    xml = f"""<feedback><report_metadata><org_name>google.com</org_name><report_id>r1</report_id>
      <date_range><begin>{int((datetime.utcnow() - timedelta(days=1)).timestamp())}</begin><end>{int(datetime.utcnow().timestamp())}</end></date_range></report_metadata>
      <policy_published><domain>x.com</domain><p>none</p></policy_published>
      <record><row><source_ip>209.85.220.41</source_ip><count>5</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
      <identifiers><header_from>x.com</header_from></identifiers><auth_results><dkim><domain>x.com</domain><selector>google</selector><result>pass</result></dkim></auth_results></record></feedback>"""
    assert client.post("/api/dmarc/reports", content=gzip.compress(xml.encode()), headers=h).status_code == 201
    monkeypatch.setattr(dns_checks, "dkim_key_info", lambda sel, d: {"found": True, "type": "rsa", "bits": 512, "revoked": False})
    sel = client.get("/api/dmarc/dkim/x.com", headers=h).json()["selectors"]
    assert sel[0]["selector"] == "google" and sel[0]["bits"] == 512 and sel[0]["status"] == "fail"


def test_dkim_key_info(monkeypatch):
    monkeypatch.setattr(dns_checks, "_txt", lambda name: {"a._domainkey.x.com": ["v=DKIM1; k=rsa; p="],
                                                          "b._domainkey.x.com": ["v=DKIM1; k=ed25519; p=abc"]}.get(name, []))
    assert dns_checks.dkim_key_info("a", "x.com") == {"found": True, "type": "rsa", "revoked": True, "bits": None}
    assert dns_checks.dkim_key_info("b", "x.com")["type"] == "ed25519"
    assert dns_checks.dkim_key_info("c", "x.com")["found"] is False


# ------------------------------------------------------------------ Domain Connect
@pytest.fixture()
def dc_on(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    monkeypatch.setattr(settings, "DOMAIN_CONNECT_PROVIDER_ID", "phishlens.test")
    monkeypatch.setattr(settings, "DOMAIN_CONNECT_KEY_DOMAIN", "dc.phishlens.test")
    monkeypatch.setattr(settings, "DOMAIN_CONNECT_PRIVATE_KEY", pem.replace("\n", "\\n"))
    monkeypatch.setattr(settings, "APP_URL", "https://pl.test")
    return key


def test_match_service():
    m = domain_connect.match_service
    assert m("_dmarc.x.com", "TXT", '"v=DMARC1; p=none"', "x.com") == ("dmarc", "", {"dmarc": "v=DMARC1; p=none"})
    assert m("_dmarc.sub.x.com", "TXT", "v=DMARC1; p=none", "x.com")[:2] == ("dmarc", "sub")
    assert m("x.com", "TXT", "v=spf1 -all", "x.com") == ("spf", "", {"spf": "v=spf1 -all"})
    assert m("sub.x.com", "TXT", "v=spf1 -all", "x.com")[:2] == ("spf", "sub")
    assert m("_dmarc.x.com", "CNAME", "x.com.ab._dmarc.h.test.", "x.com") == ("hosted-dmarc", "", {"target": "x.com.ab._dmarc.h.test"})
    assert m("mta-sts.x.com", "CNAME", "pl.test", "x.com")[0] == "mtasts-host"
    assert m("_mta-sts.x.com", "CNAME", "t.h.test", "x.com")[0] == "hosted-mtasts"
    assert m("_smtp._tls.x.com", "TXT", "v=TLSRPTv1; rua=mailto:a@x.com", "x.com")[0] == "tlsrpt"
    assert m("default._bimi.x.com", "CNAME", "t.h.test", "x.com")[0] == "hosted-bimi"
    with pytest.raises(domain_connect.DomainConnectError):
        m("_dmarc.y.com", "TXT", "v=DMARC1; p=none", "x.com")
    with pytest.raises(domain_connect.DomainConnectError):
        m("www.x.com", "CNAME", "t.h.test", "x.com")


def test_apply_url_is_signed(dc_on):
    info = {"zone": "x.com", "provider_name": "GoDaddy", "url_sync_ux": "https://dcc.example/manage", "url_api": "https://api.example"}
    url = domain_connect.apply_url(info, "dmarc", "", {"dmarc": "v=DMARC1; p=reject"}, state="s1")
    parts = urlsplit(url)
    assert parts.path == "/manage/v2/domainTemplates/providers/phishlens.test/services/dmarc/apply"
    query, sig_and_key = parts.query.split("&sig=")
    sig, key = sig_and_key.split("&key=")
    assert key == "_dck1"
    dc_on.public_key().verify(base64.b64decode(unquote(sig)), query.encode(), padding.PKCS1v15(), hashes.SHA256())
    params = dict(parse_qsl(query))
    assert params == {"domain": "x.com", "dmarc": "v=DMARC1; p=reject",
                      "redirect_uri": "https://pl.test/dashboard?dc=done", "state": "s1"}


def test_templates_and_public_key(dc_on):
    t = domain_connect.template("dmarc")
    assert t["providerId"] == "phishlens.test" and t["serviceId"] == "dmarc"
    assert t["syncPubKeyDomain"] == "dc.phishlens.test" and t["syncRedirectDomain"] == "pl.test"
    assert t["records"] == [{"type": "TXT", "host": "_dmarc", "ttl": 3600, "data": "%dmarc%",
                             "txtConflictMatchingMode": "Prefix", "txtConflictMatchingPrefix": "v=DMARC1"}]
    assert domain_connect.template("hosted-bimi")["records"][0]["pointsTo"] == "%target%"
    pub = dc_on.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    recs = domain_connect.public_key_records(pub)
    assert recs[0].startswith("p=1,a=RS256,d=") and len(recs) >= 2
    der = base64.b64decode("".join(r.split(",d=", 1)[1] for r in recs))
    assert serialization.load_der_public_key(der).public_numbers() == dc_on.public_key().public_numbers()


def test_discover(monkeypatch):
    class Ans:
        strings = [b"api.dnshost.example"]

    def resolve(name, rtype, lifetime=None):
        import dns.resolver
        if name == "_domainconnect.x.com":
            return [Ans()]
        raise dns.resolver.NXDOMAIN()
    seen = {}

    def get_json(url):
        seen["url"] = url
        return {"providerId": "dnshost", "providerDisplayName": "DNS Host",
                "urlSyncUX": "https://dc.dnshost.example", "urlAPI": "https://api.dnshost.example"}
    monkeypatch.setattr(domain_connect, "_get_json", get_json)
    info = domain_connect.discover("sub.x.com", resolver=SimpleNamespace(resolve=resolve))
    assert seen["url"] == "https://api.dnshost.example/v2/x.com/settings"
    assert info == {"zone": "x.com", "provider_id": "dnshost", "provider_name": "DNS Host",
                    "url_sync_ux": "https://dc.dnshost.example", "url_api": "https://api.dnshost.example"}
    Ans.strings = [b"bad host!"]
    assert domain_connect.discover("x.com", resolver=SimpleNamespace(resolve=resolve)) is None


def test_domain_connect_endpoints(client, dc_on, monkeypatch):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    info = {"zone": "x.com", "provider_id": "gd", "provider_name": "GoDaddy",
            "url_sync_ux": "https://dcc.example", "url_api": "https://api.example"}
    monkeypatch.setattr(domain_connect, "discover", lambda d, resolver=None: info)
    monkeypatch.setattr(domain_connect, "supports", lambda i, sid: sid == "dmarc")
    assert client.get("/api/dns/domain-connect?domain=x.com", headers=h).json() == {
        "configured": True, "supported": True, "provider": "GoDaddy", "zone": "x.com"}
    assert client.get("/api/dns/domain-connect?domain=y.com", headers=h).status_code == 403
    body = {"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=quarantine"}
    r = client.post("/api/dns/domain-connect/apply-url", json=body, headers=h)
    assert r.status_code == 200 and r.json()["url"].startswith("https://dcc.example/v2/domainTemplates/providers/phishlens.test/services/dmarc/apply?domain=x.com")
    spf = client.post("/api/dns/domain-connect/apply-url", json={**body, "name": "x.com", "value": "v=spf1 -all"}, headers=h)
    assert spf.status_code == 400 and "hasn't enabled" in spf.json()["detail"]
    assert client.post("/api/dns/domain-connect/apply-url", json={**body, "name": "_dmarc.y.com"}, headers=h).status_code == 403
    assert client.post("/api/dns/domain-connect/apply-url", json={**body, "value": "hello"}, headers=h).status_code == 400


def test_domain_connect_off_by_default(client):
    h = _auth(client, "o@x.com")
    assert client.get("/api/dns/domain-connect?domain=x.com", headers=h).json() == {"configured": False, "supported": False}
    body = {"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=none"}
    assert client.post("/api/dns/domain-connect/apply-url", json=body, headers=h).status_code == 503
