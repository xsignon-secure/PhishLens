"""No user accounts: one admin password opens the dashboard."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from app import models, workspace
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from tests.conftest import ADMIN_PASSWORD, admin_headers


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client(db):
    return TestClient(app)


def test_password_opens_the_dashboard(client):
    assert client.get("/dashboard", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/monitors").status_code == 401
    r = client.post("/api/auth/login", json={"password": "wrong"})
    assert r.status_code == 401 and r.json()["detail"] == "Wrong password"
    r = client.post("/api/auth/login", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 200 and client.cookies.get("access_token")
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/auth/me").json()["role"] == "owner"
    assert "Admin password" in client.get("/login").text


def test_no_account_routes_left(client):
    for path in ("/signup", "/forgot-password", "/reset-password", "/verify"):
        assert client.get(path).status_code == 404
    h = admin_headers(client)
    assert client.post("/api/auth/signup", json={"email": "a@b.com", "password": "x" * 12}).status_code == 404
    assert client.get("/api/team/members", headers=h).status_code == 404
    assert client.post("/api/team/invite", json={"email": "a@b.com"}, headers=h).status_code == 404
    assert client.get("/api/team/sso", headers=h).status_code == 404
    assert client.get("/scim/v2/Users", headers=h).status_code == 404
    assert client.post("/api/auth/mfa/setup", headers=h).status_code == 404


def test_dashboard_off_without_admin_password(client, monkeypatch):
    h = admin_headers(client)
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "")
    assert client.post("/api/auth/login", json={"password": ""}).status_code == 422
    assert client.post("/api/auth/login", json={"password": "anything"}).status_code == 503
    assert "The dashboard is off" in client.get("/login").text
    assert client.get("/api/monitors", headers=h).status_code == 401
    assert client.get("/").status_code == 200  # the free tools stay public


def test_changing_the_password_signs_everyone_out(client, monkeypatch):
    h = admin_headers(client)
    assert client.get("/api/monitors", headers=h).status_code == 200
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "a-new-password")
    assert client.get("/api/monitors", headers=h).status_code == 401
    assert client.post("/api/auth/login", json={"password": ADMIN_PASSWORD}).status_code == 401


def test_sign_out_everywhere(client):
    old = admin_headers(client)
    new = {"Authorization": "Bearer " + client.post("/api/auth/sessions/revoke", headers=old).json()["access_token"]}
    assert client.get("/api/monitors", headers=old).status_code == 401
    assert client.get("/api/monitors", headers=new).status_code == 200


def test_login_is_rate_limited(client):
    codes = [client.post("/api/auth/login", json={"password": "guess"}).status_code for _ in range(12)]
    assert codes[0] == 401 and codes[-1] == 429


def test_api_keys_still_work(client, db):
    h = admin_headers(client)
    key = client.post("/api/team/keys", json={"name": "SIEM"}, headers=h).json()["api_key"]
    assert client.get("/api/monitors", headers={"X-API-Key": key}).status_code == 200
    # A key left over from another team in an old database opens nothing.
    other = models.Tenant(name="Old team")
    db.add(other)
    db.flush()
    db.add(models.ApiKey(tenant_id=other.id, user_id=workspace.get_admin(db).id, name="old", prefix="plk_o",
                         key_hash=hashlib.sha256(b"plk_old").hexdigest()))
    db.commit()
    assert client.get("/api/monitors", headers={"X-API-Key": "plk_old"}).status_code == 401


def test_old_database_keeps_its_first_team(client, db):
    first = models.Tenant(name="First")
    db.add(first)
    db.flush()
    db.add(models.User(tenant_id=first.id, email="boss@first.com", role="owner", password_hash="x"))
    db.commit()
    second = models.Tenant(name="Second")
    db.add(second)
    db.flush()
    db.add(models.User(tenant_id=second.id, email="boss@second.com", role="owner", password_hash="x"))
    db.add(models.Monitor(tenant_id=first.id, domain="kept.com"))
    db.add(models.Monitor(tenant_id=second.id, domain="hidden.com"))
    db.commit()
    h = admin_headers(client)
    assert [m["domain"] for m in client.get("/api/monitors", headers=h).json()] == ["kept.com"]
    # Alerts and reports go to ADMIN_EMAIL now.
    assert workspace.get_admin(db).email == settings.ADMIN_EMAIL


def test_fresh_database_gets_one_workspace(db):
    admin = workspace.get_admin(db)
    assert admin.role == "owner" and admin.tenant.name == "PhishLens"
    assert workspace.get_admin(db).id == admin.id
    assert db.query(models.Tenant).count() == 1 and db.query(models.User).count() == 1
