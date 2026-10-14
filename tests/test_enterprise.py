"""Enterprise features: CSRF, MFA, password reset, invites, API keys, webhooks, audit."""
import hashlib
import hmac
import json

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import mailer, models, webhooks
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.scanner import engine as scan_engine


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

    def fake_checks(domain):
        return [{
            "key": "spf", "title": "SPF", "status": "pass", "score": 15, "max_score": 15,
            "details": "stubbed", "issues": [], "fixes": [],
        }]

    monkeypatch.setattr("app.scanner.scoring.run_all_checks", fake_checks)
    return TestClient(app)


def _signup(client, email, **kw):
    body = {"email": email, "password": "correct-horse-123", "company": "Acme"}
    body.update(kw)
    r = client.post("/api/auth/signup", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ CSRF
def test_csrf_blocks_cookie_mutation_without_token(client):
    _signup(client, "csrf@example.com")
    r = client.post("/api/monitors", json={"domain": "example.com"})
    assert r.status_code == 403


def test_csrf_allows_with_token_header(client):
    _signup(client, "csrf2@example.com")
    csrf = client.cookies.get("csrf_token")
    assert csrf
    r = client.post("/api/monitors", json={"domain": "example.com"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201, r.text


def test_csrf_exempt_for_bearer_even_with_cookie_jar(client):
    tok = _signup(client, "csrf3@example.com")["access_token"]
    # cookie jar holds a session cookie, but explicit Bearer auth is exempt
    r = client.post("/api/monitors", json={"domain": "example.com"},
                    headers=_bearer(tok))
    assert r.status_code == 201, r.text


# ------------------------------------------------------------------ MFA
def test_mfa_full_flow(client, db):
    data = _signup(client, "mfa@example.com")
    h = _bearer(data["access_token"])
    r = client.post("/api/auth/mfa/setup", headers=h)
    assert r.status_code == 200
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    r = client.post("/api/auth/mfa/verify", json={"code": code}, headers=h)
    assert r.status_code == 200

    # login now requires the second factor
    client.cookies.clear()
    r = client.post("/api/auth/login",
                    json={"email": "mfa@example.com", "password": "correct-horse-123"})
    assert r.status_code == 200
    assert r.json().get("mfa_required") is True
    mfa_token = r.json()["mfa_token"]

    # wrong code fails
    r = client.post("/api/auth/mfa/challenge",
                    json={"mfa_token": mfa_token, "code": "000000"})
    assert r.status_code == 401
    # right code completes login
    r = client.post("/api/auth/mfa/challenge",
                    json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_mfa_disable(client):
    data = _signup(client, "mfa2@example.com")
    h = _bearer(data["access_token"])
    secret = client.post("/api/auth/mfa/setup", headers=h).json()["secret"]
    client.post("/api/auth/mfa/verify",
                json={"code": pyotp.TOTP(secret).now()}, headers=h)
    r = client.post("/api/auth/mfa/disable",
                    json={"password": "correct-horse-123"}, headers=h)
    assert r.status_code == 200
    client.cookies.clear()
    r = client.post("/api/auth/login",
                    json={"email": "mfa2@example.com", "password": "correct-horse-123"})
    assert "access_token" in r.json()  # no MFA step anymore


# ------------------------------------------------------------------ password reset + verification
def test_password_reset_flow(client, db, monkeypatch):
    _signup(client, "reset@example.com")
    sent = {}
    monkeypatch.setattr(mailer, "send_email",
                        lambda to, subject, body: sent.update(body=body) or True)
    r = client.post("/api/auth/password/forgot", json={"email": "reset@example.com"})
    assert r.status_code == 200
    # unknown email also returns 200 (no enumeration)
    r = client.post("/api/auth/password/forgot", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    import re
    token = re.search(r"token=([A-Za-z0-9_\-]+)", sent["body"]).group(1)
    r = client.post("/api/auth/password/reset",
                    json={"token": token, "new_password": "brand-new-pass-1"})
    assert r.status_code == 200
    # token is single-use
    r = client.post("/api/auth/password/reset",
                    json={"token": token, "new_password": "another-pass-22"})
    assert r.status_code == 400
    client.cookies.clear()
    r = client.post("/api/auth/login",
                    json={"email": "reset@example.com", "password": "brand-new-pass-1"})
    assert r.status_code == 200


def test_email_verification(client, db, monkeypatch):
    data = _signup(client, "verify@example.com")
    h = _bearer(data["access_token"])
    assert data["user"]["is_verified"] is False
    tok = db.query(models.AuthToken).filter(
        models.AuthToken.purpose == "verify_email").first()
    assert tok is not None
    # need the raw token: create a fresh one via resend and capture the email
    sent = {}
    monkeypatch.setattr(mailer, "send_email",
                        lambda to, subject, body: sent.update(body=body) or True)
    client.post("/api/auth/verify/resend", headers=h)
    import re
    raw = re.search(r"token=([A-Za-z0-9_\-]+)", sent["body"]).group(1)
    r = client.post("/api/auth/verify", json={"token": raw}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=h).json()["is_verified"] is True


# ------------------------------------------------------------------ invites
def test_invite_joins_existing_tenant(client, db, monkeypatch):
    owner = _signup(client, "owner@example.com")
    ho = _bearer(owner["access_token"])
    captured = {}
    monkeypatch.setattr(mailer, "send_email",
                        lambda to, subject, body: captured.update(body=body) or True)
    r = client.post("/api/team/invite", json={"email": "member@example.com"}, headers=ho)
    assert r.status_code == 201, r.text
    import re
    raw = re.search(r"invite=([A-Za-z0-9_\-]+)", captured["body"]).group(1)

    client.cookies.clear()
    member = _signup(client, "member@example.com", invite_token=raw)
    assert member["user"]["tenant_id"] == owner["user"]["tenant_id"]
    assert member["user"]["role"] == "member"

    # member cannot invite others
    hm = _bearer(member["access_token"])
    r = client.post("/api/team/invite", json={"email": "x@example.com"}, headers=hm)
    assert r.status_code == 403


# ------------------------------------------------------------------ API keys
def test_api_key_lifecycle(client):
    owner = _signup(client, "keyowner@example.com")
    ho = _bearer(owner["access_token"])
    r = client.post("/api/team/keys", json={"name": "ci"}, headers=ho)
    assert r.status_code == 201
    raw = r.json()["api_key"]
    assert raw.startswith("plk_")

    # use the key
    r = client.get("/api/monitors", headers={"X-API-Key": raw})
    assert r.status_code == 200
    # bogus key rejected
    r = client.get("/api/monitors", headers={"X-API-Key": "plk_bogus"})
    assert r.status_code == 401
    # revoke
    key_id = client.get("/api/team/keys", headers=ho).json()[0]["id"]
    r = client.delete(f"/api/team/keys/{key_id}", headers=ho)
    assert r.status_code == 200
    r = client.get("/api/monitors", headers={"X-API-Key": raw})
    assert r.status_code == 401


# ------------------------------------------------------------------ webhooks
def test_webhook_signed_delivery(client, db, monkeypatch):
    owner = _signup(client, "hook@example.com")
    ho = _bearer(owner["access_token"])
    captured = {}

    class FakeResp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        captured["body"] = req.data
        return FakeResp()

    # Delivery goes through a no-redirect opener and refuses non-public hosts;
    # stub DNS so the example host counts as public in the sandbox.
    monkeypatch.setattr(webhooks._opener, "open", fake_urlopen)
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda host: True)
    r = client.put("/api/team/webhook",
                   json={"url": "https://hooks.example.com/x",
                         "secret": "supersecretvalue123"},
                   headers=ho)
    assert r.status_code == 200, r.text

    tenant = db.query(models.Tenant).first()
    monitor = models.Monitor(tenant_id=tenant.id, domain="example.com", last_score=90)
    db.add(monitor)
    db.commit()

    from types import SimpleNamespace
    from datetime import datetime
    scan = SimpleNamespace(score=60, grade="D", created_at=datetime(2026, 10, 9),
                           result={"checks": []})
    alerts = [models.Alert(tenant_id=tenant.id, monitor_id=monitor.id,
                           kind="score_drop", message="dropped",
                           created_at=datetime(2026, 10, 9))]
    assert webhooks.notify_alerts(db, monitor, scan, alerts) is True
    body = captured["body"]
    expected = hmac.new(b"supersecretvalue123", body, hashlib.sha256).hexdigest()
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers["x-phishlens-signature"] == "sha256=" + expected
    assert headers["x-phishlens-event"] == "monitor.alert"
    assert json.loads(body)["event"] == "monitor.alert"


# ------------------------------------------------------------------ audit
def test_audit_log_records_and_is_owner_only(client):
    owner = _signup(client, "auditowner@example.com")
    ho = _bearer(owner["access_token"])
    client.get("/api/auth/me", headers=ho)
    r = client.get("/api/team/audit", headers=ho)
    assert r.status_code == 200
    actions = [e["action"] for e in r.json()]
    assert "auth.signup" in actions

    # invite a member, then member is denied the audit log
    import re
    captured = {}
    orig_send = mailer.send_email
    mailer.send_email = lambda to, subject, body: captured.update(body=body) or True
    client.post("/api/team/invite", json={"email": "auditor@example.com"}, headers=ho)
    mailer.send_email = orig_send
    raw = re.search(r"invite=([A-Za-z0-9_\-]+)", captured["body"]).group(1)
    client.cookies.clear()
    member = _signup(client, "auditor@example.com", invite_token=raw)
    r = client.get("/api/team/audit", headers=_bearer(member["access_token"]))
    assert r.status_code == 403
