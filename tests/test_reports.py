"""VirusTotal reputation badge, PDF export, per-domain score history. No network."""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import models, pdf_report
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.scanner import engine as scan_engine, reputation
from tests.conftest import admin_login


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _vt_state():
    reputation._cache.clear()
    reputation._calls.clear()
    yield
    reputation._cache.clear()
    reputation._calls.clear()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [{
        "key": "spf", "title": "SPF", "status": "warn", "score": 11, "max_score": 15,
        "details": "Record: v=spf1 <script>alert(1)</script> ~all & more",
        "issues": ["SPF ends in ~all"], "fixes": ["Change ~all to -all"]}])
    return TestClient(app)


def _signup(client, *_args, **_kw):
    return admin_login(client, keep_cookies=True)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _vt_response(stats, status=200):
    return SimpleNamespace(status_code=status, json=lambda: {
        "data": {"attributes": {"last_analysis_stats": stats, "last_analysis_date": 1760000000}}})


# ------------------------------------------------------------------ VirusTotal
def test_reputation_off_without_key(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    assert reputation.lookup("example.com") is None


def test_reputation_summarises_vendor_stats(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "k")
    seen = {}

    def fake_get(url, timeout=None, headers=None):
        seen.update(url=url, headers=headers)
        return _vt_response({"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 30})
    monkeypatch.setattr(reputation.httpx, "get", fake_get)
    rep = reputation.lookup("example.com")
    assert rep["malicious"] == 2 and rep["suspicious"] == 1 and rep["total"] == 93
    assert rep["verdict"] == "malicious"
    assert rep["url"] == "https://www.virustotal.com/gui/domain/example.com"
    assert seen["headers"]["x-apikey"] == "k"


def test_reputation_cached_and_rate_limited(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "k")
    monkeypatch.setattr(settings, "VIRUSTOTAL_RATE_PER_MIN", 2)
    calls = []
    monkeypatch.setattr(reputation.httpx, "get",
                        lambda url, **kw: calls.append(url) or _vt_response({"harmless": 90}))
    reputation.lookup("a.com")
    reputation.lookup("a.com")  # cache hit
    reputation.lookup("b.com")
    assert reputation.lookup("c.com") is None  # budget spent: badge omitted, scan unaffected
    assert len(calls) == 2


def test_reputation_failure_never_breaks_scan(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "k")

    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(reputation.httpx, "get", boom)
    assert reputation.lookup("example.com") is None
    monkeypatch.setattr(reputation.httpx, "get", lambda *a, **k: SimpleNamespace(status_code=429))
    assert reputation.lookup("example.com") is None


def test_reputation_attached_to_scan_but_not_scored(client, monkeypatch):
    monkeypatch.setattr(reputation, "lookup", lambda d: {
        "source": "VirusTotal", "known": True, "malicious": 5, "suspicious": 0, "total": 90,
        "verdict": "malicious", "url": "https://www.virustotal.com/gui/domain/example.com"})
    data = client.post("/api/scans/public", json={"domain": "example.com"}).json()
    assert data["result"]["reputation"]["malicious"] == 5
    assert data["score"] == round(100 * 11 / 15)  # unchanged by the reputation verdict


# ------------------------------------------------------------------ PDF
def test_pdf_render_escapes_untrusted_text():
    pdf = pdf_report.render({"domain": "example.com", "score": 72, "grade": "C", "checks": [{
        "title": "SPF", "status": "fail", "score": 0, "max_score": 15,
        "details": "<b>unclosed & <script>", "issues": ["<i>"], "fixes": ["v=spf1 -all"]}],
        "action_plan": [{"check": "SPF", "fix": "v=spf1 <x> -all", "points": 15}],
        "reputation": {"known": True, "malicious": 0, "suspicious": 0, "total": 90,
                       "url": "https://www.virustotal.com/gui/domain/example.com"}},
        history={"points": [], "trend": {"from_score": 60, "to_score": 72, "delta": 12,
                                         "since": "2026-09-01T00:00:00Z"}})
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_pdf_for_tenant_scan(client):
    h = _bearer(_signup(client, "pdf@example.com")["access_token"])
    scan = client.post("/api/scans", json={"domain": "example.com"}, headers=h).json()
    r = client.get(f"/api/scans/{scan['id']}/pdf", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert 'filename="phishlens-example.com-' in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")


def test_pdf_tenant_isolation(client):
    ha = _bearer(_signup(client, "pa@example.com")["access_token"])
    scan = client.post("/api/scans", json={"domain": "example.com"}, headers=ha).json()
    # a tenant scan is not reachable via the anonymous-scan route either
    assert client.get(f"/api/scans/public/{scan['id']}/pdf").status_code == 404
    # nor via the shared route until it is shared
    assert client.get(f"/api/scans/shared/{scan['id']}/pdf").status_code == 404
    client.post(f"/api/scans/{scan['id']}/share", headers=ha)
    assert TestClient(app).get(f"/api/scans/shared/{scan['id']}/pdf").status_code == 200


def test_pdf_for_anonymous_landing_scan(client):
    data = TestClient(app).post("/api/scans/public", json={"domain": "example.com"}).json()
    r = TestClient(app).get(f"/api/scans/public/{data['id']}/pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


# ------------------------------------------------------------------ history
def _add_scan(db, tenant_id, score, days_ago, domain="example.com"):
    db.add(models.Scan(tenant_id=tenant_id, domain=domain, score=score, grade="C",
                       result={"checks": []},
                       created_at=datetime.utcnow() - timedelta(days=days_ago)))
    db.commit()


def test_history_trend_since_last_month(db):
    t = models.Tenant(name="Acme")
    db.add(t)
    db.commit()
    for score, days in [(50, 70), (72, 35), (78, 10), (85, 0)]:
        _add_scan(db, t.id, score, days)
    _add_scan(db, t.id, 10, 1, domain="other.com")  # other domains don't leak in
    h = scan_engine.score_history(db, t.id, "example.com")
    assert [p["score"] for p in h["points"]] == [50, 72, 78, 85]
    assert h["trend"]["from_score"] == 72 and h["trend"]["to_score"] == 85
    assert h["trend"]["delta"] == 13


def test_history_falls_back_to_oldest_scan(db):
    t = models.Tenant(name="Acme")
    db.add(t)
    db.commit()
    _add_scan(db, t.id, 60, 5)
    _add_scan(db, t.id, 70, 0)
    assert scan_engine.score_history(db, t.id, "example.com")["trend"]["delta"] == 10


def test_history_needs_two_scans(db):
    t = models.Tenant(name="Acme")
    db.add(t)
    db.commit()
    _add_scan(db, t.id, 60, 0)
    assert scan_engine.score_history(db, t.id, "example.com")["trend"] is None


def test_scan_and_monitor_responses_carry_history(client):
    h = _bearer(_signup(client, "hist@example.com")["access_token"])
    client.post("/api/scans", json={"domain": "example.com"}, headers=h)
    scan = client.post("/api/scans", json={"domain": "example.com"}, headers=h).json()
    assert len(scan["history"]["points"]) == 2
    assert scan["history"]["trend"]["delta"] == 0
    client.post("/api/monitors", json={"domain": "example.com"}, headers=h)
    mon = client.get("/api/monitors", headers=h).json()[0]
    assert len(mon["history"]["points"]) == 3
    r = client.get("/api/scans/history/example.com", headers=h).json()
    assert r["domain"] == "example.com" and len(r["points"]) == 3


def test_public_scan_has_no_history(client):
    data = client.post("/api/scans/public", json={"domain": "example.com"}).json()
    assert "history" not in data
