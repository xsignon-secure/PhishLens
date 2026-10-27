"""SSO, hosted records, one-click DNS, forensic reports, white-label."""
import base64
import hashlib
import hmac
import io
import json
import time
import urllib.parse

import httpx
import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app import (branding, crypto, dns_providers, forensic, hosted, mailer, models,
                 pdf_report, sso)
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [{
        "key": "dmarc", "title": "DMARC", "status": "fail", "score": 0, "max_score": 20,
        "details": "stubbed", "issues": [],
        "fixes": [f'Add TXT at _dmarc.{domain}: "v=DMARC1; p=none; rua=mailto:dmarc@{domain}" then move on.']}])
    return TestClient(app)


def _auth(client, email, company="Acme"):
    r = client.post("/api/auth/signup", json={"email": email, "password": "correct-horse-123",
                                              "company": company})
    assert r.status_code == 201, r.text
    client.cookies.clear()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _tenant(db, email):
    return db.query(models.User).filter(models.User.email == email).first().tenant


# ------------------------------------------------------------------ fully free
def test_no_billing_or_paywall(client):
    h = _auth(client, "self@hosted.com")
    assert client.get("/api/billing", headers=h).status_code == 404
    assert client.put("/api/team/branding", json={"brand_name": "X"}, headers=h).status_code == 200
    for d in ("a.com", "b.com", "c.com", "d.com", "e.com"):  # no 3-domain cap
        assert client.post("/api/monitors", json={"domain": d}, headers=h).status_code == 201


def test_operator_can_cap_monitors(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_MONITORS_PER_TEAM", 1)
    h = _auth(client, "cap@hosted.com")
    assert client.post("/api/monitors", json={"domain": "a.com"}, headers=h).status_code == 201
    r = client.post("/api/monitors", json={"domain": "b.com"}, headers=h)
    assert r.status_code == 429 and "allows 1" in r.json()["detail"]


# ------------------------------------------------------------------ SSO
@pytest.fixture()
def idp(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = jwk.construct(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), "RS256").to_dict()
    pub.update(kid="k1", use="sig")
    issuer = "https://idp.example.com"
    docs = {issuer + "/.well-known/openid-configuration": {
                "issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"},
            issuer + "/jwks": {"keys": [pub]}}
    monkeypatch.setattr(sso, "_get_json", lambda url: docs[url])
    monkeypatch.setattr(sso.webhooks, "url_allowed", lambda url: True)
    sso._discovery_cache.clear()
    sso._jwks_cache.clear()
    state = {"claims": {}}

    def fake_token(url, data=None, timeout=None, follow_redirects=None):
        claims = {"iss": issuer, "aud": "client-1", "exp": int(time.time()) + 300,
                  "iat": int(time.time()), "sub": "u1", **state["claims"]}
        tok = jwt.encode(claims, pem.decode(), algorithm="RS256", headers={"kid": "k1"})
        return httpx.Response(200, json={"id_token": tok, "access_token": "x"})
    monkeypatch.setattr(sso.httpx, "post", fake_token)
    return {"issuer": issuer, "state": state}


def _setup_sso(client, h, idp, enforced=False):
    r = client.put("/api/team/sso", headers=h, json={
        "issuer": idp["issuer"], "client_id": "client-1", "client_secret": "s3cret",
        "email_domain": "acme.com", "enforced": enforced})
    assert r.status_code == 200, r.text
    return r


def _sso_login(client, idp, email):
    r = client.get("/api/auth/sso/start", params={"email": email}, follow_redirects=False)
    assert r.status_code == 303, r.text
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    assert q["code_challenge_method"] == "S256" and q["client_id"] == "client-1"
    idp["state"]["claims"] = {"email": email, "email_verified": True, "nonce": q["nonce"]}
    return client.get("/api/auth/sso/callback", params={"code": "c", "state": q["state"]},
                      follow_redirects=False)


def test_sso_provisions_member_and_signs_in(client, db, idp):
    h = _auth(client, "boss@acme.com")
    _setup_sso(client, h, idp)
    t = _tenant(db, "boss@acme.com")
    assert crypto.decrypt(t.sso_client_secret) == "s3cret" and t.sso_client_secret != "s3cret"
    r = _sso_login(client, idp, "new.hire@acme.com")
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    assert "access_token" in r.cookies or "access_token" in client.cookies
    u = db.query(models.User).filter(models.User.email == "new.hire@acme.com").first()
    assert u.tenant_id == t.id and u.role == "member" and u.is_verified


def test_sso_rejects_wrong_domain_and_bad_nonce(client, idp):
    h = _auth(client, "boss@acme.com")
    _setup_sso(client, h, idp)
    r = client.get("/api/auth/sso/start", params={"email": "x@acme.com"}, follow_redirects=False)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    idp["state"]["claims"] = {"email": "intruder@evil.com", "nonce": q["nonce"]}
    r = client.get("/api/auth/sso/callback", params={"code": "c", "state": q["state"]}, follow_redirects=False)
    assert "sso_error" in r.headers["location"]
    r = client.get("/api/auth/sso/start", params={"email": "x@acme.com"}, follow_redirects=False)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    idp["state"]["claims"] = {"email": "x@acme.com", "nonce": "replayed"}
    r = client.get("/api/auth/sso/callback", params={"code": "c", "state": q["state"]}, follow_redirects=False)
    assert "nonce" in urllib.parse.unquote(r.headers["location"])
    r = client.get("/api/auth/sso/callback", params={"code": "c", "state": "forged"}, follow_redirects=False)
    assert "sso_error" in r.headers["location"]


def test_sso_domain_must_match_owner_and_enforcement(client, db, idp):
    h = _auth(client, "boss@acme.com")
    r = client.put("/api/team/sso", headers=h, json={
        "issuer": idp["issuer"], "client_id": "c", "client_secret": "s", "email_domain": "gmail.com"})
    assert r.status_code == 400
    _setup_sso(client, h, idp, enforced=True)
    member = models.User(tenant_id=_tenant(db, "boss@acme.com").id, email="m@acme.com", role="member",
                         is_verified=True, password_hash=__import__("app.security", fromlist=["x"])
                         .hash_password("correct-horse-123"))
    db.add(member)
    db.commit()
    r = client.post("/api/auth/login", json={"email": "m@acme.com", "password": "correct-horse-123"})
    assert r.status_code == 403
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"email": "boss@acme.com", "password": "correct-horse-123"})
    assert r.status_code == 200  # owner keeps break-glass password login


# ------------------------------------------------------------------ hosted records
class _Rec:
    def __init__(self, text):
        self.text = text
        self.strings = [text.encode()]
        self.exchange = text
        self.target = text

    def to_text(self):
        return self.text


class _Resolver:
    def __init__(self, zone):
        self.zone = zone

    def resolve(self, name, rtype, lifetime=None):
        vals = self.zone.get((name, rtype))
        if not vals:
            raise Exception("NXDOMAIN")
        return [_Rec(v) for v in vals]


def test_clean_config_validation():
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("dmarc", {"p": "block"}, "x.com")
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("spf", {"sources": ["ptr"]}, "x.com")
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("spf", {"sources": ["ip4:999.1.1.1"]}, "x.com")
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("mta_sts", {"mode": "enforce", "mx": ["bad host!"]}, "x.com")
    cfg = hosted.clean_config("dmarc", {"p": "reject", "pct": 50, "rua": ["mailto:R@X.com"]}, "x.com")
    assert hosted.dmarc_value(cfg) == "v=DMARC1; p=reject; t=y; rua=mailto:r@x.com"
    cfg = hosted.clean_config("dmarc", {"p": "reject", "np": "reject", "rua": ["r@x.com"]}, "x.com")
    assert hosted.dmarc_value(cfg) == "v=DMARC1; p=reject; np=reject; rua=mailto:r@x.com"


def test_spf_flattening_and_chaining():
    zone = {
        ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com ~all"],
        ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip6:2001:4860:4000::/36 ~all"],
        ("x.com", "MX"): ["mx1.x.com"],
        ("mx1.x.com", "A"): ["203.0.113.25"],
    }
    terms = hosted.flatten_spf(["include:_spf.google.com", "mx", "ip4:198.51.100.0/24",
                                "include:unresolvable.example"], "x.com", _Resolver(zone))
    assert terms == ["ip4:35.190.247.0/24", "ip4:64.233.160.0/19", "ip6:2001:4860:4000::/36",
                     "ip4:203.0.113.25", "ip4:198.51.100.0/24", "include:unresolvable.example"]
    rec = models.HostedRecord(tenant_id="t1", domain="x.com", kind="spf", config={"sources": [], "all": "-all"})
    many = [f"ip4:10.0.{i}.0/24" for i in range(60)]
    recs = hosted.spf_records(rec, many)
    assert len(recs) > 1 and all(len(v) <= hosted.SPF_CHUNK for v in recs.values())
    names = list(recs)
    assert f"include:{names[1]}" in recs[names[0]]
    assert sum(v.count("ip4:") for v in recs.values()) == 60


def _cf_transport(store: dict):
    """In-memory Cloudflare DNS API."""
    def handler(request: httpx.Request):
        path, m = request.url.path, request.method
        if path.endswith("/user/tokens/verify"):
            return httpx.Response(200, json={"success": True, "result": {"status": "active"}})
        if path.endswith("/zones"):
            name = request.url.params["name"]
            ok = name in ("x.com", "hosted.test")
            return httpx.Response(200, json={"success": True, "result": [{"id": "z-" + name, "name": name}] if ok else []})
        if path.endswith("/dns_records") and m == "GET":
            p = request.url.params
            res = [r for r in store.values() if r["name"] == p["name"] and r["type"] == p["type"]]
            return httpx.Response(200, json={"success": True, "result": res})
        if path.endswith("/dns_records") and m == "POST":
            body = json.loads(request.content)
            rid = f"r{len(store) + 1}"
            store[rid] = {"id": rid, **body}
            return httpx.Response(200, json={"success": True, "result": store[rid]})
        rid = path.rsplit("/", 1)[1]
        if m == "PUT":
            store[rid] = {"id": rid, **json.loads(request.content)}
        elif m == "DELETE":
            store.pop(rid, None)
        return httpx.Response(200, json={"success": True, "result": {}})
    return httpx.MockTransport(handler)


@pytest.fixture()
def hosted_on(monkeypatch):
    store = {}
    monkeypatch.setattr(settings, "HOSTED_ZONE", "hosted.test")
    monkeypatch.setattr(settings, "HOSTED_CLOUDFLARE_TOKEN", "cf-platform")
    monkeypatch.setattr(settings, "HOSTED_CLOUDFLARE_ZONE_ID", "z-hosted.test")
    monkeypatch.setattr(settings, "HOSTED_DMARC_RUA", "dmarc@reports.hosted.test")
    monkeypatch.setattr(settings, "MTA_STS_TARGET", "mta-sts.hosted.test")
    real = dns_providers.Cloudflare
    monkeypatch.setattr(dns_providers, "Cloudflare", lambda token, transport=None: real(token, _cf_transport(store)))
    monkeypatch.setattr(hosted, "provider", lambda transport=None: real("cf-platform", _cf_transport(store)))
    return store


def test_hosted_dmarc_publish_update_delete(client, hosted_on):
    h = _auth(client, "o@x.com")
    assert client.put("/api/hosted/x.com/dmarc", json={"config": {"p": "none"}}, headers=h).status_code == 400
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    r = client.put("/api/hosted/x.com/dmarc", json={"config": {"p": "none"}}, headers=h)
    assert r.status_code == 200, r.text
    rec = r.json()
    name = next(iter(rec["published"]))
    assert name.startswith("x.com.") and name.endswith("._dmarc.hosted.test")
    assert rec["published"][name] == "v=DMARC1; p=none; rua=mailto:dmarc@reports.hosted.test"
    # external-report authorisation for the hosted rua mailbox
    assert "x.com._report._dmarc.reports.hosted.test" in rec["published"]
    assert rec["customer_records"][0] == {"name": "_dmarc.x.com", "type": "CNAME", "value": name,
                                          "note": "Delete any existing TXT record at this name first."}
    client.put("/api/hosted/x.com/dmarc", json={"config": {"p": "reject"}}, headers=h)
    txts = [r["content"] for r in hosted_on.values() if r["name"] == name]
    assert txts == ["v=DMARC1; p=reject; rua=mailto:dmarc@reports.hosted.test"]
    assert client.delete("/api/hosted/x.com/dmarc", headers=h).status_code == 200
    assert not hosted_on


def test_hosted_records_isolated_between_tenants(client, hosted_on):
    a = _auth(client, "a@x.com")
    b = _auth(client, "b@y.com")
    for h in (a, b):
        client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    ra = client.put("/api/hosted/x.com/dmarc", json={"config": {"p": "reject"}}, headers=a).json()
    rb = client.put("/api/hosted/x.com/dmarc", json={"config": {"p": "none"}}, headers=b).json()
    assert set(ra["published"]).isdisjoint(set(rb["published"]) - {"x.com._report._dmarc.reports.hosted.test"})
    assert client.get("/api/hosted", headers=b).json()["records"][0]["config"]["p"] == "none"
    assert client.delete("/api/hosted/x.com/spf", headers=b).status_code == 404


def test_mta_sts_policy_served_by_host(client, db, hosted_on):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    r = client.put("/api/hosted/x.com/mta_sts", json={"config": {"mode": "enforce", "mx": ["*.mail.x.com"]}},
                   headers=h)
    assert r.status_code == 200, r.text
    assert next(iter(r.json()["published"].values())).startswith("v=STSv1; id=")
    pol = client.get("/.well-known/mta-sts.txt", headers={"Host": "mta-sts.x.com"})
    assert pol.status_code == 200
    assert pol.text == "version: STSv1\r\nmode: enforce\r\nmx: *.mail.x.com\r\nmax_age: 604800\r\n"
    assert client.get("/.well-known/mta-sts.txt", headers={"Host": "mta-sts.nothosted.com"}).status_code == 404


def test_hosted_disabled_without_zone(client):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    assert client.get("/api/hosted", headers=h).json()["configured"] is False
    assert client.put("/api/hosted/x.com/dmarc", json={"config": {}}, headers=h).status_code == 503


# ------------------------------------------------------------------ one-click DNS
def test_apply_fix_through_customer_cloudflare(client, db, hosted_on):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    assert client.put("/api/team/cloudflare", json={"token": "t" * 40}, headers=h).status_code == 200
    assert _tenant(db, "o@x.com").dns_token != "t" * 40  # encrypted at rest
    body = {"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=none"}
    r = client.post("/api/dns/apply", json=body, headers=h)
    assert r.json()["result"] == "created"
    assert client.post("/api/dns/apply", json=body, headers=h).json()["result"] == "unchanged"
    body["value"] = "v=DMARC1; p=reject"
    assert client.post("/api/dns/apply", json=body, headers=h).json()["result"] == "updated"
    # not a domain of this tenant / not an email-auth record / CNAME elsewhere
    assert client.post("/api/dns/apply", json={**body, "name": "_dmarc.bank.com"}, headers=h).status_code == 403
    assert client.post("/api/dns/apply", json={"name": "x.com", "type": "TXT", "value": "google-site-verification=1"},
                       headers=h).status_code == 400
    assert client.post("/api/dns/apply", json={"name": "www.x.com", "type": "CNAME", "value": "evil.com"},
                       headers=h).status_code == 400
    assert client.post("/api/dns/apply", json={"name": "mta-sts.x.com", "type": "CNAME",
                                               "value": "mta-sts.hosted.test"}, headers=h).json()["ok"]


def test_cloudflare_upsert_keeps_unrelated_txt():
    store = {"r1": {"id": "r1", "name": "x.com", "type": "TXT", "content": "google-site-verification=abc"},
             "r2": {"id": "r2", "name": "x.com", "type": "TXT", "content": "v=spf1 -all"}}
    cf = dns_providers.Cloudflare("t", _cf_transport(store))
    assert cf.upsert("z", "x.com", "TXT", '"v=spf1 include:_spf.google.com -all"') == "updated"
    assert store["r1"]["content"] == "google-site-verification=abc"
    assert store["r2"]["content"] == "v=spf1 include:_spf.google.com -all"


# ------------------------------------------------------------------ forensic
_ARF = b"""From: dmarc-noreply@reporter.example
To: dmarc@x.com
Subject: Report Domain: x.com
Message-ID: <ruf-1@reporter.example>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="b1"

--b1
Content-Type: text/plain

This is a DMARC failure report.
--b1
Content-Type: message/feedback-report

Feedback-Type: auth-failure
User-Agent: reporter/1.0
Version: 1
Original-Mail-From: <ceo@x.com>
Arrival-Date: Tue, 21 Oct 2026 10:00:00 +0000
Source-IP: 198.51.100.7
Reported-Domain: x.com
Auth-Failure: dmarc
Delivery-Result: reject
Authentication-Results: mx.reporter.example; dmarc=fail header.from=x.com

--b1
Content-Type: text/rfc822-headers

From: "CEO" <ceo@x.com>
To: victim@reporter.example
Subject: Urgent wire transfer

--b1--
"""


def test_parse_forensic_report():
    r = forensic.parse(_ARF)
    assert r["domain"] == "x.com" and r["source_ip"] == "198.51.100.7"
    assert r["auth_failure"] == "dmarc" and r["delivery_result"] == "reject"
    assert r["header_from"] == "ceo@x.com" and r["subject"] == "Urgent wire transfer"
    assert r["reporter"] == "reporter.example"
    with pytest.raises(forensic.ForensicError):
        forensic.parse(b"From: a@b.c\nSubject: hi\n\nhello")


def test_forensic_upload_list_and_mailbox(client, db):
    from scripts import fetch_dmarc_reports as fetch

    h = _auth(client, "o@x.com")
    r = client.post("/api/dmarc/forensic", content=_ARF, headers=h)
    assert r.status_code == 201 and not r.json()["duplicate"]
    assert client.post("/api/dmarc/forensic", content=_ARF, headers=h).json()["duplicate"]
    rows = client.get("/api/dmarc/forensic", headers=h).json()
    assert len(rows) == 1 and rows[0]["subject"] == "Urgent wire transfer"
    other = _auth(client, "b@y.com")
    assert client.get("/api/dmarc/forensic", headers=other).json() == []
    client.post("/api/monitors", json={"domain": "x.com"}, headers=other)
    assert fetch.file_message(db, _ARF) == (1, 0)  # filed for the tenant monitoring x.com


# ------------------------------------------------------------------ white-label
def _png(w=40, h=20):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (79, 70, 229)).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def test_logo_validation():
    assert base64.b64decode(branding.clean_logo(_png()))[:4] == b"\x89PNG"
    assert branding.clean_logo("data:image/png;base64," + _png())
    with pytest.raises(branding.BrandingError):
        branding.clean_logo(base64.b64encode(b"<svg onload=alert(1)>").decode())
    with pytest.raises(branding.BrandingError):
        branding.clean_color("red")


def test_branding_on_pdf_shared_report_and_alerts(client, db, monkeypatch):
    h = _auth(client, "msp@acme-it.com")
    r = client.put("/api/team/branding", headers=h, json={
        "brand_name": "Acme IT", "brand_color": "#112233", "report_footer": "Call 555-0100",
        "logo": _png(), "alert_emails": ["tickets@psa.example"]})
    assert r.status_code == 200, r.text
    scan = client.post("/api/scans", json={"domain": "client.com"}, headers=h).json()
    pdf = client.get(f"/api/scans/{scan['id']}/pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF" and b"Acme IT" in pdf.content
    client.post(f"/api/scans/{scan['id']}/share", headers=h)
    page = client.get(f"/r/{scan['id']}").text
    assert "Prepared by Acme IT" in page and "Call 555-0100" in page
    sent = {}
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, body: sent.update(to=to, subject=subject, body=body) or True)
    t = _tenant(db, "msp@acme-it.com")
    mon = models.Monitor(tenant_id=t.id, domain="client.com", client="Client Co")
    db.add(mon)
    db.commit()
    s = db.query(models.Scan).first()
    mailer.notify_monitor_alerts(db, mon, s, [models.Alert(kind="score_drop", message="dropped")], 90)
    assert "tickets@psa.example" in sent["to"] and "msp@acme-it.com" in sent["to"]
    assert sent["subject"].startswith("[Client Co]") and "Acme IT monitor alert" in sent["body"]


def test_monitor_client_tag(client):
    h = _auth(client, "o@x.com")
    mid = client.post("/api/monitors", json={"domain": "x.com", "client": "Bakery"}, headers=h).json()["id"]
    assert client.get("/api/monitors", headers=h).json()[0]["client"] == "Bakery"
    assert client.patch(f"/api/monitors/{mid}", json={"client": "Florist"}, headers=h).json()["client"] == "Florist"


def test_unbranded_pdf_still_renders():
    assert pdf_report.render({"domain": "x.com", "score": 50, "grade": "D", "checks": []})[:4] == b"%PDF"


# ------------------------------------------------------------------ built-in scheduler
def test_scheduler_off_by_default_and_runs_rescans(monkeypatch):
    from app import scheduler
    from scripts import rescan
    monkeypatch.setattr(settings, "RESCAN_INTERVAL_HOURS", 0)
    assert scheduler.start() is None
    calls = []
    monkeypatch.setattr(rescan, "run", lambda **kw: calls.append(kw) or {"done": 0})
    waits = iter([False, True])  # skip the startup delay, then stop after one run
    monkeypatch.setattr(scheduler._stop, "wait", lambda secs: next(waits))
    scheduler._loop(168)
    assert calls == [{"min_age_hours": 167}]
