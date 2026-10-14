"""Monitor rescan + email alert tests. No network, no real SMTP."""
from datetime import datetime
from types import SimpleNamespace

import pytest

from app import mailer, models
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.scanner import engine as scan_engine


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    session = SessionLocal()
    yield session
    session.close()


def _make_tenant(db, owner_email="owner@example.com"):
    tenant = models.Tenant(name="Acme")
    db.add(tenant)
    db.flush()
    db.add_all([
        models.User(tenant_id=tenant.id, email=owner_email, password_hash="x", role="owner"),
        models.User(tenant_id=tenant.id, email="member@example.com", password_hash="x", role="member"),
    ])
    db.commit()
    return tenant


def _make_monitor(db, tenant, domain="example.com", last_score=80):
    monitor = models.Monitor(tenant_id=tenant.id, domain=domain,
                             last_score=last_score, last_checked_at=datetime.utcnow())
    db.add(monitor)
    db.commit()
    return monitor


def _stub_scan(score=60, grade="D", failed=("SPF",)):
    return SimpleNamespace(
        score=score, grade=grade,
        result={"checks": [{"title": title, "status": "fail"} for title in failed]},
        created_at=datetime(2026, 10, 9, 12, 0, 0),
    )


def test_send_email_noop_when_unconfigured():
    assert mailer.is_configured() is False
    assert mailer.send_email(["a@example.com"], "hi", "body") is False


def test_send_email_composes_message(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@example.com")
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = (host, port)

        def starttls(self, context=None):
            sent["tls"] = True
            sent["tls_verifies"] = context is not None

        def send_message(self, msg):
            sent["msg"] = msg

        def quit(self):
            sent["quit"] = True

    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    assert mailer.send_email(["owner@example.com"], "score alert", "body text") is True
    assert sent["host"] == ("smtp.example.com", 587)
    assert sent["tls"] is True
    assert sent["msg"]["To"] == "owner@example.com"
    assert "score alert" in sent["msg"]["Subject"]
    assert "body text" in sent["msg"].get_content()


def test_notify_goes_to_owners_only(db, monkeypatch):
    tenant = _make_tenant(db)
    monitor = _make_monitor(db, tenant)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@example.com")
    captured = {}
    monkeypatch.setattr(
        mailer, "send_email",
        lambda to, subject, body: captured.update(to=to, subject=subject, body=body) or True,
    )
    alerts = [models.Alert(tenant_id=tenant.id, monitor_id=monitor.id,
                           kind="score_drop", message="dropped")]
    assert mailer.notify_monitor_alerts(db, monitor, _stub_scan(), alerts, prev_score=80) is True
    assert captured["to"] == ["owner@example.com"]  # members excluded
    assert "80 -> 60 (D)" in captured["body"]
    assert "/dashboard" in captured["body"]


def test_rescan_records_drop_and_failure_alerts(db, monkeypatch):
    tenant = _make_tenant(db)
    monitor = _make_monitor(db, tenant, last_score=80)
    monkeypatch.setattr(scan_engine, "run_scan",
                        lambda db_, domain, tenant_id=None: _stub_scan(score=60))
    emailed = {}
    monkeypatch.setattr(mailer, "notify_monitor_alerts",
                        lambda *a: emailed.update(called=True) or True)
    result = scan_engine.rescan_monitor(db, monitor)
    assert result["scan"].score == 60
    assert {a.kind for a in result["alerts"]} == {"score_drop", "check_failed"}
    assert emailed.get("called") is True
    db.refresh(monitor)
    assert monitor.last_score == 60
    assert monitor.last_checked_at is not None
    assert db.query(models.Alert).count() == 2


def test_rescan_quiet_when_score_improves(db, monkeypatch):
    tenant = _make_tenant(db)
    monitor = _make_monitor(db, tenant, last_score=50)
    monkeypatch.setattr(scan_engine, "run_scan",
                        lambda db_, domain, tenant_id=None: _stub_scan(score=90, grade="A", failed=()))
    result = scan_engine.rescan_monitor(db, monitor)
    assert result["alerts"] == []
    assert result["emailed"] is False
    assert db.query(models.Alert).count() == 0
