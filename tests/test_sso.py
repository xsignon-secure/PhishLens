"""Single sign-on (SAML 2.0 and OpenID Connect) on top of admin-created accounts."""
import base64
import re
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from lxml import etree
from signxml import XMLSigner

from app import models, saml, sso
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import TEST_PASSWORD, login_as, make_user

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
        a = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(a, key=key, cert=cert)
    resp = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{saml.NS["samlp"]}" ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'</samlp:Response>')
    resp.append(a)
    return base64.b64encode(etree.tostring(resp)).decode()


METADATA = (f'<md:EntityDescriptor xmlns:md="{saml.NS["md"]}" xmlns:ds="{saml.NS["ds"]}" entityID="{IDP}">'
            f'<md:IDPSSODescriptor protocolSupportEnumeration="{saml.NS["samlp"]}">'
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
            f'{"".join(CERT.splitlines()[1:-1])}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="https://idp.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>')


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def owner(db):
    return make_user(db, "boss@acme.com", company="Acme")


@pytest.fixture()
def saml_client(db, owner, monkeypatch):
    monkeypatch.setattr("app.webhooks.url_allowed", lambda u: True)
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    r = c.put("/api/team/saml", headers=h, json={"metadata_xml": METADATA, "email_domain": "acme.com"})
    assert r.status_code == 200, r.text
    assert r.json()["protocol"] == "saml" and r.json()["saml_sso_url"] == "https://idp.example.com/sso"
    c.cookies.clear()
    return c


def _start(c, email="member@acme.com"):
    r = c.get("/api/auth/sso/start", params={"email": email}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/sso?")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    req = zlib.decompress(base64.b64decode(q["SAMLRequest"]), -15).decode()
    return re.search(r'ID="([^"]+)"', req).group(1), q["RelayState"]


def _post(c, saml_response, relay):
    return c.post("/api/auth/saml/acs", data={"SAMLResponse": saml_response, "RelayState": relay},
                  follow_redirects=False)


def _error(r):
    assert r.status_code == 303 and "sso_error" in r.headers["location"], r.headers.get("location")
    return urllib.parse.unquote(r.headers["location"])


def test_only_owners_configure_sso(db, owner, monkeypatch):
    monkeypatch.setattr("app.webhooks.url_allowed", lambda u: True)
    admin = make_user(db, "admin@acme.com", role="admin", tenant=owner.tenant)
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, admin, keep_cookies=False)['access_token']}"}
    assert c.put("/api/team/saml", headers=h, json={"metadata_xml": METADATA,
                                                     "email_domain": "acme.com"}).status_code == 403


def test_saml_signs_in_existing_member_once(saml_client, db, owner):
    make_user(db, "member@acme.com", role="member", tenant=owner.tenant, mfa=False)
    rid, relay = _start(saml_client)
    r = _post(saml_client, _response(_assertion("member@acme.com", rid)), relay)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers["location"]
    assert saml_client.get("/api/auth/me").json()["email"] == "member@acme.com"
    # The same response can't be replayed.
    saml_client.cookies.clear()
    _error(_post(saml_client, _response(_assertion("member@acme.com", rid)), relay))
    assert saml_client.get("/api/auth/me").status_code == 401


def test_saml_never_creates_accounts(saml_client, db):
    rid, relay = _start(saml_client, "stranger@acme.com")
    msg = _error(_post(saml_client, _response(_assertion("stranger@acme.com", rid)), relay))
    assert "Ask your administrator" in msg
    assert not db.query(models.User).filter_by(email="stranger@acme.com").first()


def test_saml_first_sign_in_skips_the_temporary_password(saml_client, db, owner):
    u = make_user(db, "new@acme.com", role="member", tenant=owner.tenant, mfa=False)
    u.status, u.must_change_password = "pending", True
    db.commit()
    rid, relay = _start(saml_client, "new@acme.com")
    assert _post(saml_client, _response(_assertion("new@acme.com", rid)), relay).headers["location"] == "/dashboard"
    db.refresh(u)
    assert u.status == "active" and not u.must_change_password


def test_saml_rejects_bad_responses(saml_client, db, owner):
    make_user(db, "x@acme.com", role="member", tenant=owner.tenant, mfa=False)
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


def test_saml_rejects_signature_wrapping(saml_client, db, owner):
    make_user(db, "member@acme.com", role="member", tenant=owner.tenant, mfa=False)
    rid, relay = _start(saml_client)
    signed = etree.fromstring(base64.b64decode(_response(_assertion("member@acme.com", rid))))
    evil = etree.fromstring(_assertion("boss@acme.com", rid).replace('ID="_a1"', 'ID="_evil"'))
    signed.insert(1, evil)
    assert "exactly one" in _error(_post(saml_client, base64.b64encode(etree.tostring(signed)).decode(), relay))
    rid, relay = _start(saml_client)
    xml = base64.b64decode(_response(_assertion("member@acme.com", rid))).replace(b"member@", b"boss@")
    assert "signature" in _error(_post(saml_client, base64.b64encode(xml).decode(), relay))


def test_required_sso_blocks_passwords_for_members_not_owners(db, owner, monkeypatch):
    monkeypatch.setattr("app.webhooks.url_allowed", lambda u: True)
    make_user(db, "member@acme.com", role="member", tenant=owner.tenant, mfa=False)
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    assert c.put("/api/team/saml", headers=h, json={"metadata_xml": METADATA, "email_domain": "acme.com",
                                                     "enforced": True}).status_code == 200
    r = c.post("/api/auth/login", json={"email": "member@acme.com", "password": TEST_PASSWORD})
    assert r.status_code == 403 and "SSO" in r.json()["detail"]
    # A wrong password still gets the generic answer (no hint that SSO is on).
    assert c.post("/api/auth/login", json={"email": "member@acme.com", "password": "nope"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": "boss@acme.com", "password": TEST_PASSWORD}).json()["next"] == "mfa"


def test_sso_domain_must_be_the_owners_and_unique(db, owner, monkeypatch):
    monkeypatch.setattr("app.webhooks.url_allowed", lambda u: True)
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    assert c.put("/api/team/saml", headers=h, json={"metadata_xml": METADATA,
                                                     "email_domain": "other.com"}).status_code == 400
    other = make_user(db, "boss@acme.com.invalid", company="Squatter")
    other.tenant.sso_email_domain = "acme.com"
    db.commit()
    assert c.put("/api/team/saml", headers=h, json={"metadata_xml": METADATA,
                                                     "email_domain": "acme.com"}).status_code == 409


def test_oidc_callback_signs_in_existing_user(db, owner, monkeypatch):
    make_user(db, "member@acme.com", role="member", tenant=owner.tenant, mfa=False)
    owner.tenant.sso_issuer, owner.tenant.sso_client_id = "https://idp.example.com", "cid"
    owner.tenant.sso_email_domain, owner.tenant.sso_protocol = "acme.com", "oidc"
    db.commit()
    monkeypatch.setattr(sso, "discover", lambda issuer: {"authorization_endpoint": "https://idp.example.com/auth"})
    monkeypatch.setattr(sso, "finish", lambda tenant, code, state: {"email": "member@acme.com"})
    c = TestClient(app)
    r = c.get("/api/auth/sso/start", params={"email": "member@acme.com"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/auth?")
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))["state"]
    r = c.get("/api/auth/sso/callback", params={"code": "abc", "state": state}, follow_redirects=False)
    assert r.headers["location"] == "/dashboard"
    assert c.get("/api/auth/me").json()["email"] == "member@acme.com"
    # A forged state is refused.
    c2 = TestClient(app)
    c2.get("/api/auth/sso/start", params={"email": "member@acme.com"}, follow_redirects=False)
    assert "sso_error" in c2.get("/api/auth/sso/callback", params={"code": "abc", "state": "forged"},
                                 follow_redirects=False).headers["location"]
