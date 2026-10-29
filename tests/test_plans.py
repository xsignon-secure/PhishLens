"""Hosted plans: off by default (everything allowed), and when on, the
platform admin sets Free / Pro / MSP per company and the server enforces it."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import dmarc_reports, models, plans
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from app.routers.dmarc import store_report
from tests.conftest import ADMIN_PASSWORD, login_as, make_user

H = {"X-CSRF-Token": "test-csrf"}


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [])
    return TestClient(app)


@pytest.fixture()
def plans_on(monkeypatch):
    monkeypatch.setattr(settings, "PLANS_ENABLED", True)


def _set_plan(db, user, plan):
    user.tenant.plan = plan
    db.commit()


def test_plans_off_means_everything_is_included(client, db):
    owner = make_user(db)
    assert plans.plan_key(owner.tenant) == "msp"
    login_as(client, owner)
    p = client.get("/api/team/plan").json()
    assert p["enabled"] is False and "api_keys" in p["features"]
    assert client.post("/api/team/keys", json={"name": "k"}, headers=H).status_code == 201


def test_free_plan_limits_domains_and_users(client, db, plans_on):
    owner = make_user(db)
    login_as(client, owner)
    for d in ("a.com", "b.com"):
        assert client.post("/api/monitors", json={"domain": d}, headers=H).status_code == 201
    r = client.post("/api/monitors", json={"domain": "c.com"}, headers=H)
    assert r.status_code == 402 and "Free plan includes 2 monitored domains" in r.json()["detail"]
    assert client.post("/api/users", json={"email": "m1@x.com", "send_email": False}, headers=H).status_code == 201
    r = client.post("/api/users", json={"email": "m2@x.com", "send_email": False}, headers=H)
    assert r.status_code == 402
    rows = client.post("/api/users/import", json={"csv": "m3@x.com,M,member", "send_email": False}, headers=H).json()
    assert rows["created"] == 0 and "plan includes 2 users" in rows["rows"][0]["error"]
    usage = client.get("/api/team/plan").json()
    assert usage["plan"] == "free" and usage["usage"] == {"monitors": 2, "users": 2, "dmarc_domains": 0}


def test_free_plan_locks_paid_features(client, db, plans_on):
    owner = make_user(db)
    login_as(client, owner)
    r = client.post("/api/team/keys", json={"name": "k"}, headers=H)
    assert r.status_code == 402 and r.json()["detail"].startswith("API keys needs the Pro plan")
    assert client.put("/api/team/webhook", json={"url": "https://hooks.example.com/x", "secret": "s" * 20},
                      headers=H).status_code == 402
    assert client.put("/api/team/report-schedule", json={"schedule": "weekly"}, headers=H).status_code == 402
    assert client.put("/api/team/report-schedule", json={"schedule": "off"}, headers=H).status_code == 200
    # Extra alert addresses are in every plan; a brand name is MSP.
    assert client.put("/api/team/branding", json={"alert_emails": ["t@psa.example"]}, headers=H).status_code == 200
    assert client.put("/api/team/branding", json={"brand_name": "Acme IT"}, headers=H).status_code == 402
    assert client.put("/api/team/integrations/siem", json={"kind": "syslog"}, headers=H).status_code == 402


def test_upgrade_unlocks_and_downgrade_keeps_data(client, db, plans_on):
    owner = make_user(db)
    _set_plan(db, owner, "pro")
    login_as(client, owner)
    assert client.post("/api/team/keys", json={"name": "k"}, headers=H).status_code == 201
    assert client.put("/api/team/branding", json={"brand_name": "Acme IT"}, headers=H).status_code == 402  # MSP
    _set_plan(db, owner, "msp")
    assert client.put("/api/team/branding", json={"brand_name": "Acme IT"}, headers=H).status_code == 200
    from app import branding
    db.refresh(owner)
    assert branding.for_tenant(owner.tenant)["name"] == "Acme IT"
    _set_plan(db, owner, "free")
    db.refresh(owner)
    assert branding.for_tenant(owner.tenant) is None  # hidden, not deleted
    assert owner.tenant.brand_name == "Acme IT"
    assert len(client.get("/api/team/keys").json()) == 1


def _report(domain, begin):
    return {"report_id": f"r-{domain}-{begin:%s}", "org_name": "google.com", "domain": domain,
            "date_begin": begin, "date_end": begin + timedelta(days=1), "policy": {},
            "records": [{"count": 1, "dkim": "pass", "spf": "pass"}]}


def test_free_plan_dmarc_domains_and_history(client, db, plans_on):
    owner = make_user(db)
    now = datetime.utcnow()
    store_report(db, owner.tenant_id, _report("a.com", now - timedelta(days=2)))
    store_report(db, owner.tenant_id, _report("a.com", now - timedelta(days=40)))  # same domain: fine
    with pytest.raises(dmarc_reports.ReportError, match="1 domain"):
        store_report(db, owner.tenant_id, _report("b.com", now))
    login_as(client, owner)
    assert len(client.get("/api/dmarc/reports").json()) == 1  # 14 days of history on Free
    _set_plan(db, owner, "pro")
    assert len(client.get("/api/dmarc/reports").json()) == 2


def test_platform_admin_sets_plans(client, db, plans_on):
    assert client.post("/api/platform/login", json={"password": ADMIN_PASSWORD}).status_code == 200
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    r = client.post("/api/platform/companies", json={"name": "Acme", "owner_email": "boss@acme.com",
                                                     "send_email": False, "plan": "pro"}, headers=h).json()
    assert r["plan"] == "pro" and r["plans_enabled"] is True
    r = client.post(f"/api/platform/companies/{r['id']}/plan", json={"plan": "msp"}, headers=h)
    assert r.json()["plan"] == "msp"
    assert client.post(f"/api/platform/companies/{r.json()['id']}/plan", json={"plan": "gold"}, headers=h).status_code == 422
    assert db.query(models.AuditEvent).filter(models.AuditEvent.action == "platform.company_plan").count() == 1
    page = client.get("/platform")
    assert page.status_code == 200 and 'name="plan"' in page.text


def test_rescans_follow_the_plan(db, plans_on, monkeypatch):
    from scripts import rescan
    owner = make_user(db)
    seen = []
    monkeypatch.setattr("app.scanner.engine.rescan_monitor",
                        lambda db, m, check_lookalikes: seen.append((m.domain, check_lookalikes)) or
                        {"alerts": [], "scan": type("S", (), {"score": 90})(), "emailed": False})
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="a.com",
                          last_checked_at=datetime.utcnow() - timedelta(hours=30)))
    db.commit()
    rescan.run(min_age_hours=1)
    assert seen == []  # Free: weekly
    _set_plan(db, owner, "pro")
    rescan.run(min_age_hours=1)
    assert seen == [("a.com", True)]  # Pro: daily, with lookalike watch
