"""Enterprise features: CSRF, MFA, password reset, invites, API keys, webhooks, audit."""
import hashlib
import hmac
import json


import pytest
from fastapi.testclient import TestClient

from app import models, webhooks
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import admin_login


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


def _signup(client, *_args, **_kw):
    return admin_login(client, keep_cookies=True)


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


# ------------------------------------------------------------------ password reset + verification


# ------------------------------------------------------------------ invites


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
