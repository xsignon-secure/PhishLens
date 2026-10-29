"""Regression tests for the 2026-10 audit fixes. No network: DNS/HTTP stubbed."""
import base64
import ssl
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

from app import mailer, models
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.scanner import dns_checks, engine as scan_engine, net, web_checks
from tests.conftest import admin_login


# ------------------------------------------------------------------ fixtures
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
        "key": "spf", "title": "SPF", "status": "pass", "score": 15, "max_score": 15,
        "details": "stubbed", "issues": [], "fixes": []}])
    return TestClient(app)


def _signup(client, *_args, **_kw):
    return admin_login(client, keep_cookies=True)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ DKIM
def test_dkim_real_world_spki_key_passes():
    """Providers publish SubjectPublicKeyInfo keys; these used to read as 'unknown length'."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    spki = base64.b64encode(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    assert spki.startswith("MIIBIjANBgkqhkiG9w0B")
    assert dns_checks._dkim_key_bits(spki) == 2048
    dns_checks._txt = lambda name: {
        "google._domainkey.x.com": [f"v=DKIM1; k=rsa; p={spki}"]}.get(name, [])
    r = dns_checks.check_dkim("x.com")
    assert r["status"] == "pass" and r["score"] == 15


def test_dkim_ed25519_key_passes():
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dns_checks._txt = lambda name: {
        "default._domainkey.x.com": [f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}"]
    }.get(name, [])
    r = dns_checks.check_dkim("x.com")
    assert r["status"] == "pass" and "Ed25519" in r["details"]


# ------------------------------------------------------------------ MTA-STS
class _FakeMX:
    def __init__(self, host):
        self.exchange = host + "."
        self.preference = 10


def _sts_setup(monkeypatch, policy, mx_hosts):
    dns_checks._txt = lambda name: {"_mta-sts.x.com": ["v=STSv1; id=20261012"]}.get(name, [])
    monkeypatch.setattr(net, "is_public_host", lambda host: True)
    import httpx
    monkeypatch.setattr(httpx, "get", lambda url, **kw: SimpleNamespace(status_code=200, text=policy))
    monkeypatch.setattr(dns_checks._resolver, "resolve",
                        lambda name, rtype, lifetime=None: [_FakeMX(h) for h in mx_hosts])


def test_mta_sts_enforce_policy_parsed(monkeypatch):
    """Policy files are 'key: value' lines; they used to be parsed as 'k=v' and always failed."""
    _sts_setup(monkeypatch,
               "version: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmax_age: 604800\n",
               ["x-com.mail.protection.outlook.com"])
    r = dns_checks.check_mta_sts("x.com")
    assert r["status"] == "pass" and r["score"] == 10, r


def test_mta_sts_mx_mismatch_flagged(monkeypatch):
    _sts_setup(monkeypatch, "version: STSv1\nmode: enforce\nmx: mx.other.net\nmax_age: 86400\n",
               ["mx1.x.com"])
    r = dns_checks.check_mta_sts("x.com")
    assert r["status"] == "warn"
    assert any("matches none" in i for i in r["issues"])


def test_mta_sts_wildcard_matches_one_label_only():
    assert dns_checks._mx_matches("*.example.com", "mx.example.com")
    assert not dns_checks._mx_matches("*.example.com", "a.b.example.com")
    assert not dns_checks._mx_matches("*.example.com", "example.com")


# ------------------------------------------------------------------ DNSBL / DMARC / SPF
def test_dnsbl_refusal_codes_are_not_listings(monkeypatch):
    def fake_resolve(name, rtype, lifetime=None):
        if rtype == "MX":
            return [_FakeMX("mx.x.com")]
        if "spamhaus" in name:
            return ["127.255.255.254"]  # "query via public resolver" refusal
        raise Exception("NXDOMAIN")
    monkeypatch.setattr(dns_checks._resolver, "resolve", fake_resolve)
    monkeypatch.setattr(dns_checks.socket, "gethostbyname", lambda h: "203.0.113.5")
    r = dns_checks.check_dnsbl("x.com")
    assert r["status"] == "pass", r


def test_dnsbl_real_listing_detected(monkeypatch):
    def fake_resolve(name, rtype, lifetime=None):
        if rtype == "MX":
            return [_FakeMX("mx.x.com")]
        if "spamcop" in name:
            return ["127.0.0.2"]
        raise Exception("NXDOMAIN")
    monkeypatch.setattr(dns_checks._resolver, "resolve", fake_resolve)
    monkeypatch.setattr(dns_checks.socket, "gethostbyname", lambda h: "203.0.113.5")
    r = dns_checks.check_dnsbl("x.com")
    assert r["status"] == "fail" and "bl.spamcop.net" in r["issues"][0]


def test_dmarc_multiple_records_fail():
    dns_checks._txt = lambda name: {"_dmarc.x.com": [
        "v=DMARC1; p=reject; rua=mailto:a@x.com", "v=DMARC1; p=none"]}.get(name, [])
    r = dns_checks.check_dmarc("x.com")
    assert r["status"] == "fail" and r["score"] == 0


def test_spf_counts_nested_include_lookups():
    nested = {f"inc{i}.x.com": [f"v=spf1 include:deep{i}a.net include:deep{i}b.net -all"]
              for i in range(4)}
    dns_checks._txt = lambda name: {
        "x.com": ["v=spf1 " + " ".join(f"include:inc{i}.x.com" for i in range(4)) + " -all"],
        **nested}.get(name, [])
    r = dns_checks.check_spf("x.com")
    # 4 top-level + 8 nested = 12 > 10: only visible when includes are followed
    assert r["status"] == "fail", r["details"]


def test_spf_bare_all_is_plus_all():
    dns_checks._txt = lambda name: {"x.com": ["v=spf1 a mx all"]}.get(name, [])
    r = dns_checks.check_spf("x.com")
    assert r["status"] == "fail" and r["score"] == 2


def test_spf_redirect_inherits_all_qualifier():
    dns_checks._txt = lambda name: {
        "x.com": ["v=spf1 redirect=_spf.x.com"],
        "_spf.x.com": ["v=spf1 ip4:203.0.113.0/24 -all"]}.get(name, [])
    r = dns_checks.check_spf("x.com")
    assert r["status"] == "pass", r


def test_dnssec_uses_zone_not_public_suffix(monkeypatch):
    """example.co.uk must not be credited with co.uk's DS record."""
    import dns.name
    monkeypatch.setattr(dns_checks.dns.resolver, "zone_for_name",
                        lambda name, resolver=None, lifetime=None: dns.name.from_text("example.co.uk"))

    def fake_resolve(name, rtype, lifetime=None):
        if name == "co.uk" and rtype == "DS":
            return ["ds"]
        raise Exception("NoAnswer")
    monkeypatch.setattr(dns_checks._resolver, "resolve", fake_resolve)
    assert dns_checks.check_dnssec("example.co.uk")["status"] == "warn"


# ------------------------------------------------------------------ web checks
def test_untrusted_certificate_is_a_failure(monkeypatch):
    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(web_checks.socket, "create_connection", lambda *a, **k: FakeSock())

    def bad_wrap(self, sock, server_hostname=None):
        err = ssl.SSLCertVerificationError("certificate verify failed")
        err.verify_message = "certificate has expired"
        raise err
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", bad_wrap)
    r = web_checks.check_tls_cert("x.com")
    assert r["status"] == "fail" and "expired" in r["details"]


def test_safe_get_refuses_private_hosts():
    with pytest.raises(ValueError):
        net.safe_get("http://127.0.0.1/", timeout=1)
    assert not net.is_public_ip("10.0.0.1")
    assert not net.is_public_ip("100.64.0.1")  # CGNAT
    assert not net.is_public_ip("::ffff:192.168.1.1")
    assert net.is_public_ip("93.184.216.34")


# ------------------------------------------------------------------ web app wiring
def test_logged_in_user_can_use_landing_page_scan(client):
    _signup(client, "landing@example.com")  # cookie jar now holds a session
    r = client.post("/api/scans/public", json={"domain": "example.com"})
    assert r.status_code == 200, r.text


def test_logout_with_csrf_header_clears_session(client):
    _signup(client, "logout@example.com")
    csrf = client.cookies.get("csrf_token")
    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    client.cookies.clear()
    assert client.get("/api/auth/me").status_code == 401


def test_login_is_rate_limited(client):
    _signup(client, "brute@example.com")
    statuses = [client.post("/api/auth/login", json={
        "email": "brute@example.com", "password": "wrong-password"}).status_code
        for _ in range(12)]
    assert 429 in statuses


def test_removing_monitor_with_alerts(client, db):
    h = _bearer(_signup(client, "mon@example.com")["access_token"])
    mid = client.post("/api/monitors", json={"domain": "example.com"}, headers=h).json()["id"]
    monitor = db.get(models.Monitor, mid)
    db.add(models.Alert(tenant_id=monitor.tenant_id, monitor_id=mid,
                        kind="score_drop", message="x"))
    db.commit()
    assert client.delete(f"/api/monitors/{mid}", headers=h).status_code == 200
    assert db.query(models.Alert).filter_by(monitor_id=mid).count() == 0


def test_failed_baseline_scan_leaves_no_monitor(client, db, monkeypatch):
    from fastapi import HTTPException

    def refuse(db_, domain, tenant_id=None):
        raise HTTPException(status_code=400, detail="Domain does not resolve")
    monkeypatch.setattr(scan_engine, "run_scan", refuse)
    h = _bearer(_signup(client, "mon2@example.com")["access_token"])
    assert client.post("/api/monitors", json={"domain": "nope.example.org"}, headers=h).status_code == 400
    assert db.query(models.Monitor).count() == 0


def test_persistent_failures_do_not_realert(db, monkeypatch):
    tenant = models.Tenant(name="Acme")
    db.add(tenant)
    db.flush()
    monitor = models.Monitor(tenant_id=tenant.id, domain="example.com", last_score=60,
                             last_checked_at=datetime.utcnow() - timedelta(days=7))
    db.add(monitor)
    db.add(models.Scan(tenant_id=tenant.id, domain="example.com", score=60, grade="D",
                       result={"checks": [{"title": "SPF", "status": "fail"}]}))
    db.commit()
    monkeypatch.setattr(scan_engine, "run_scan", lambda db_, d, tenant_id=None: SimpleNamespace(
        score=60, grade="D", created_at=datetime.utcnow(),
        result={"checks": [{"title": "SPF", "status": "fail"}]}))
    monkeypatch.setattr(mailer, "notify_monitor_alerts", lambda *a: True)
    result = scan_engine.rescan_monitor(db, monitor)
    assert result["alerts"] == []


def test_webhook_to_private_address_rejected(client):
    h = _bearer(_signup(client, "hook2@example.com")["access_token"])
    r = client.put("/api/team/webhook", headers=h,
                   json={"url": "https://169.254.169.254/latest", "secret": "x" * 20})
    assert r.status_code == 400


def test_shared_report_binds_interactions(client, db):
    _signup(client, "share@example.com")
    tenant = db.query(models.Tenant).first()
    scan = models.Scan(tenant_id=tenant.id, domain="example.com", score=80, grade="B",
                       result={"domain": "example.com", "score": 80, "grade": "B", "checks": []},
                       is_public=True)
    db.add(scan)
    db.commit()
    html = TestClient(app).get(f"/r/{scan.id}").text
    assert "bindReportInteractions" in html


def test_request_id_on_csrf_rejection(client):
    _signup(client, "rid@example.com")
    r = client.post("/api/monitors", json={"domain": "example.com"})
    assert r.status_code == 403
    assert r.headers.get("x-request-id")


def test_dns_timeout_is_not_reported_as_missing_record(monkeypatch):
    import dns.exception
    from app.scanner import scoring

    def timeout(*a, **k):
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns_checks._resolver, "resolve", timeout)
    r = scoring._run_check(dns_checks.check_dmarc, "x.com")
    assert r["errored"] and r["max_score"] == 0 and r["status"] == "warn"


def test_incomplete_rescan_does_not_alert(db, monkeypatch):
    tenant = models.Tenant(name="Acme")
    db.add(tenant)
    db.flush()
    monitor = models.Monitor(tenant_id=tenant.id, domain="example.com", last_score=90)
    db.add(monitor)
    db.commit()
    monkeypatch.setattr(scan_engine, "run_scan", lambda db_, d, tenant_id=None: SimpleNamespace(
        score=40, grade="F", created_at=datetime.utcnow(),
        result={"checks": [{"title": "DMARC", "status": "warn", "errored": True}]}))
    result = scan_engine.rescan_monitor(db, monitor)
    assert result["alerts"] == []
    db.refresh(monitor)
    assert monitor.last_score == 90  # baseline kept


def test_smtp_tls_unreachable_port_25_is_unscored(monkeypatch):
    from app.scanner import dns_checks
    monkeypatch.setattr(dns_checks._resolver, "resolve", lambda *a, **k: [
        type("R", (), {"preference": 10, "exchange": "mx.example.com."})()])
    monkeypatch.setattr(dns_checks.net, "is_public_host", lambda h: True)

    def refuse(self, host, port):
        raise TimeoutError("timed out")
    monkeypatch.setattr(dns_checks.smtplib.SMTP, "connect", refuse)
    r = dns_checks.check_smtp_tls("example.com")
    assert r["max_score"] == 0 and r["score"] == 0
    assert "Not tested" in r["details"] and not r.get("errored")
