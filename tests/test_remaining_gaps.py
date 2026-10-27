"""Route 53 / GoDaddy one-click fixes, phishing URL checker, SAML, translations."""
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


# ------------------------------------------------------------------ SAML
import base64  # noqa: E402
import urllib.parse  # noqa: E402
import zlib  # noqa: E402
from datetime import timedelta  # noqa: E402

from cryptography import x509 as cx509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from lxml import etree  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from app import models, saml  # noqa: E402
from app.database import Base, SessionLocal, engine as sa_engine  # noqa: E402
from app.main import app  # noqa: E402

IDP = "https://idp.example.com/saml"


def _keypair(cn="idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (cx509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM).decode())


KEY, CERT = _keypair()
EVIL_KEY, EVIL_CERT = _keypair("evil")


def _assertion(email, rid, *, issuer=IDP, audience=None, recipient=None, minutes=5):
    now = datetime.now(timezone.utc)
    ts = lambda d: (now + d).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    return (f'<saml:Assertion xmlns:saml="{saml.NS["saml"]}" ID="_a1" Version="2.0" IssueInstant="{ts(timedelta())}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>'
            f'<saml:Subject><saml:NameID>{email}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData InResponseTo="{rid}" Recipient="{recipient or saml.acs_url()}" '
            f'NotOnOrAfter="{ts(timedelta(minutes=minutes))}"/></saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="{ts(timedelta(minutes=-1))}" NotOnOrAfter="{ts(timedelta(minutes=minutes))}">'
            f'<saml:AudienceRestriction><saml:Audience>{audience or saml.sp_entity_id()}</saml:Audience>'
            f'</saml:AudienceRestriction></saml:Conditions></saml:Assertion>')


def _response(assertion_xml, *, key=KEY, cert=CERT, sign=True):
    a = etree.fromstring(assertion_xml)
    if sign:
        # Real IdPs use exclusive c14n, so the signature survives being embedded in the Response.
        a = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(a, key=key, cert=cert)
    resp = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{saml.NS["samlp"]}" ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'</samlp:Response>')
    resp.append(a)
    return base64.b64encode(etree.tostring(resp)).decode()


@pytest.fixture()
def saml_client(monkeypatch):
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    monkeypatch.setattr("app.webhooks.url_allowed", lambda u: True)
    c = TestClient(app)
    r = c.post("/api/auth/signup", json={"email": "boss@acme.com", "password": "correct-horse-123", "company": "Acme"})
    assert r.status_code == 201
    c.cookies.clear()
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    metadata = (f'<md:EntityDescriptor xmlns:md="{saml.NS["md"]}" xmlns:ds="{saml.NS["ds"]}" entityID="{IDP}">'
                f'<md:IDPSSODescriptor protocolSupportEnumeration="{saml.NS["samlp"]}">'
                f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
                f'{"".join(CERT.splitlines()[1:-1])}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
                f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
                f'Location="https://idp.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>')
    r = c.put("/api/team/saml", headers=h, json={"metadata_xml": metadata, "email_domain": "acme.com"})
    assert r.status_code == 200, r.text
    assert r.json()["protocol"] == "saml" and r.json()["saml_sso_url"] == "https://idp.example.com/sso"
    return c


def _start(c, email="new.hire@acme.com"):
    r = c.get("/api/auth/sso/start", params={"email": email}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/sso?")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    req = zlib.decompress(base64.b64decode(q["SAMLRequest"]), -15).decode()
    rid = re.search(r'ID="([^"]+)"', req).group(1)
    assert saml.acs_url() in req
    return rid, q["RelayState"]


def _post(c, saml_response, relay):
    return c.post("/api/auth/saml/acs", data={"SAMLResponse": saml_response, "RelayState": relay},
                  follow_redirects=False)


def test_saml_metadata_endpoint(saml_client):
    r = saml_client.get("/api/auth/saml/metadata")
    assert r.status_code == 200 and saml.acs_url() in r.text and "EntityDescriptor" in r.text


def test_saml_signs_in_and_provisions_member(saml_client):
    rid, relay = _start(saml_client)
    r = _post(saml_client, _response(_assertion("new.hire@acme.com", rid)), relay)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers["location"]
    db = SessionLocal()
    u = db.query(models.User).filter(models.User.email == "new.hire@acme.com").first()
    assert u and u.role == "member" and u.is_verified
    db.close()
    # the same response can't be replayed
    r = _post(saml_client, _response(_assertion("new.hire@acme.com", rid)), relay)
    assert "sso_error" in r.headers["location"]


def _error(r):
    assert r.status_code == 303 and "sso_error" in r.headers["location"], r.headers.get("location")
    return urllib.parse.unquote(r.headers["location"])


def test_saml_rejects_bad_responses(saml_client):
    cases = [
        (lambda rid: _response(_assertion("x@acme.com", rid), key=EVIL_KEY, cert=EVIL_CERT), "signature"),
        (lambda rid: _response(_assertion("x@acme.com", rid), sign=False), "didn't sign"),
        (lambda rid: _response(_assertion("x@acme.com", "_other")), "doesn't match"),
        (lambda rid: _response(_assertion("x@acme.com", rid, audience="https://other.example")), "different service"),
        (lambda rid: _response(_assertion("x@acme.com", rid, issuer="https://evil.example")), "different identity"),
        (lambda rid: _response(_assertion("x@acme.com", rid, minutes=-10)), "expired"),
        (lambda rid: _response(_assertion("x@evil.com", rid)), "@acme.com"),
    ]
    for build, expect in cases:
        rid, relay = _start(saml_client)
        assert expect in _error(_post(saml_client, build(rid), relay)), expect


def test_saml_rejects_signature_wrapping(saml_client):
    rid, relay = _start(saml_client)
    signed = etree.fromstring(base64.b64decode(_response(_assertion("boss@acme.com", rid))))
    # Attacker adds a second, unsigned assertion for another user.
    evil = etree.fromstring(_assertion("boss@acme.com", rid).replace('ID="_a1"', 'ID="_evil"'))
    signed.insert(1, evil)
    assert "exactly one" in _error(_post(saml_client, base64.b64encode(etree.tostring(signed)).decode(), relay))
    # Or tampers with the signed assertion's email.
    rid, relay = _start(saml_client)
    xml = base64.b64decode(_response(_assertion("new.hire@acme.com", rid))).replace(b"new.hire@", b"boss@")
    assert "signature" in _error(_post(saml_client, base64.b64encode(xml).decode(), relay))


def test_saml_requires_matching_relay_state(saml_client):
    rid, _ = _start(saml_client)
    assert "mismatch" in _error(_post(saml_client, _response(_assertion("a@acme.com", rid)), "forged"))


# ------------------------------------------------------------------ translations
import glob  # noqa: E402

from app import i18n  # noqa: E402


def _template_strings():
    keys = set()
    for f in glob.glob("app/templates/*.html"):
        keys |= {m.replace('\\"', '"') for m in re.findall(r'_\("((?:[^"\\]|\\.)*)"\)', open(f, encoding="utf-8").read())}
    return keys


def test_every_catalog_covers_every_template_string():
    keys = _template_strings()
    assert len(keys) > 50
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
    assert "Mot de passe oublié ?" in r.text
    c.cookies.clear()
    assert "Scan my domain" in c.get("/").text
