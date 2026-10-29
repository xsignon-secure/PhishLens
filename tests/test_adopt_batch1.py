"""Setup wizard, alert levels + DNS change timeline, observations, DNSSEC
split, "email me this report" and the SPF builder's include tree."""
from datetime import datetime
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient

from app import mailer, models
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.scanner import dns_checks, dns_snapshot, observations
from app.scanner import engine as scan_engine
from tests.conftest import admin_headers

REAL_SNAPSHOT = dns_snapshot.snapshot  # conftest stubs it per test


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
        "key": "dmarc", "title": "DMARC", "status": "warn", "score": 10, "max_score": 20,
        "details": "p=none", "issues": ["DMARC policy is none."], "fixes": ["Raise the policy."]}])
    return TestClient(app)


def _auth(client, *_args, **_kw):
    return admin_headers(client)


# ------------------------------------------------------------------ snapshots
def test_snapshot_diff_and_describe():
    old = {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=none"], "MX": ["10 mx.x.com"]}
    new = {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"], "MX": [], "DKIM": ["v=DKIM1; p=abc"]}
    changes = dns_snapshot.diff(old, new)
    assert [c["record"] for c in changes] == ["DMARC", "MX"]  # DKIM had no baseline
    assert "changed from v=DMARC1; p=none to v=DMARC1; p=reject" in dns_snapshot.describe(changes[0])
    assert dns_snapshot.describe(changes[1]) == "MX record removed (was: 10 mx.x.com)"
    assert dns_snapshot.describe({"record": "BIMI", "old": [], "new": ["v=BIMI1"]}) == "BIMI record added: v=BIMI1"
    assert dns_snapshot.diff(None, new) == []


def test_snapshot_is_none_when_dns_times_out(monkeypatch):
    def resolve(name, rtype, lifetime=None):
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns_checks._resolver, "resolve", resolve)
    assert REAL_SNAPSHOT("x.com") is None


# ------------------------------------------------------------------ alert levels
def _setup(db, level, prev_dns, new_dns, prev_failed=(), failed=(), last_score=80, score=80):
    tenant = models.Tenant(name="Acme")
    db.add(tenant)
    db.flush()
    db.add(models.User(tenant_id=tenant.id, email="o@x.com", password_hash="x", role="owner"))
    monitor = models.Monitor(tenant_id=tenant.id, domain="x.com", alert_level=level,
                             last_score=last_score, last_checked_at=datetime.utcnow())
    db.add(monitor)
    db.add(models.Scan(tenant_id=tenant.id, domain="x.com", score=last_score, grade="B", result={
        "checks": [{"key": k.lower(), "title": k, "status": "fail"} for k in prev_failed], "dns": prev_dns}))
    db.commit()
    stub = SimpleNamespace(score=score, grade="B", created_at=datetime.utcnow(), result={
        "checks": [{"key": k.lower(), "title": k, "status": "fail"} for k in failed], "dns": new_dns})
    return monitor, stub


@pytest.mark.parametrize("level,kinds", [
    ("none", set()),
    ("essential", {"check_failed", "dns_changed"}),
    ("balanced", {"score_drop", "check_failed"}),
    ("comprehensive", {"score_drop", "check_failed", "dns_changed"}),
])
def test_alert_levels(db, monkeypatch, level, kinds):
    monitor, stub = _setup(db, level,
                           prev_dns={"DMARC": ["v=DMARC1; p=reject"], "MX": ["10 mx.x.com"]},
                           new_dns={"DMARC": ["v=DMARC1; p=none"], "MX": ["10 mx2.x.com"]},
                           failed=("DMARC", "SPF"), score=60)
    monkeypatch.setattr(scan_engine, "run_scan", lambda db_, d, tenant_id=None: stub)
    monkeypatch.setattr(mailer, "notify_monitor_alerts", lambda *a: True)
    result = scan_engine.rescan_monitor(db, monitor)
    assert {a.kind for a in result["alerts"]} == kinds
    # Every change is recorded for the timeline, whatever the level.
    assert {c.record for c in db.query(models.DnsChange).all()} == {"DMARC", "MX"}
    if level == "essential":
        by_kind = {a.kind: a.message for a in result["alerts"]}
        assert "DMARC" in by_kind["check_failed"] and "SPF" not in by_kind["check_failed"]
        assert "MX" not in by_kind["dns_changed"]
    if level == "comprehensive":
        msg = next(a.message for a in result["alerts"] if a.kind == "dns_changed")
        assert "DMARC record changed" in msg and "MX record changed" in msg


def test_alert_on_drop_off_means_no_alerts(db, monkeypatch):
    monitor, stub = _setup(db, "comprehensive", {"SPF": ["a"]}, {"SPF": ["b"]}, failed=("SPF",), score=10)
    monitor.alert_on_drop = False
    db.commit()
    monkeypatch.setattr(scan_engine, "run_scan", lambda db_, d, tenant_id=None: stub)
    assert scan_engine.rescan_monitor(db, monitor)["alerts"] == []
    assert db.query(models.DnsChange).count() == 1


# ------------------------------------------------------------------ API
def test_monitor_alert_level_and_changes_endpoint(client, db):
    h = _auth(client)
    r = client.post("/api/monitors", json={"domain": "x.com", "alert_level": "essential"}, headers=h)
    assert r.status_code == 201, r.text
    mid = r.json()["id"]
    assert client.post("/api/monitors", json={"domain": "y.com", "alert_level": "loud"}, headers=h).status_code == 422
    mons = client.get("/api/monitors", headers=h).json()
    assert mons[0]["alert_level"] == "essential"
    client.patch(f"/api/monitors/{mid}", json={"client": "Acme"}, headers=h)
    r = client.patch(f"/api/monitors/{mid}", json={"alert_level": "comprehensive"}, headers=h)
    assert r.json() == {"id": mid, "client": "Acme", "alert_level": "comprehensive"}  # client kept

    assert client.get(f"/api/monitors/{mid}/changes", headers=h).json() == {"domain": "x.com", "changes": []}
    mon = db.query(models.Monitor).get(mid)
    db.add(models.DnsChange(tenant_id=mon.tenant_id, monitor_id=mid, domain="x.com",
                            record="SPF", old=["v=spf1 -all"], new=[]))
    db.commit()
    changes = client.get(f"/api/monitors/{mid}/changes", headers=h).json()["changes"]
    assert changes[0]["record"] == "SPF" and changes[0]["new"] == []
    assert client.delete(f"/api/monitors/{mid}", headers=h).status_code in (200, 204)
    assert db.query(models.DnsChange).count() == 0


def test_email_report_goes_to_own_address(client, monkeypatch):
    h = _auth(client)
    sid = client.post("/api/scans", json={"domain": "x.com"}, headers=h).json()["id"]
    assert client.post(f"/api/scans/{sid}/email", headers=h).status_code == 503  # no SMTP
    sent = {}
    monkeypatch.setattr(mailer, "is_configured", lambda: True)
    monkeypatch.setattr(mailer, "send_email",
                        lambda to, subject, body, attachments=None, **k: sent.update(to=to, att=attachments) or True)
    r = client.post(f"/api/scans/{sid}/email", headers=h)
    assert r.json() == {"ok": True, "to": "owner@x.com"}
    assert sent["to"] == ["owner@x.com"]
    name, data, mime = sent["att"][0]
    assert mime == "application/pdf" and data.startswith(b"%PDF")


def test_spf_tree_endpoint(client, monkeypatch):
    zone = {"_spf.google.com": "v=spf1 include:_netblocks.google.com ~all",
            "_netblocks.google.com": "v=spf1 ip4:203.0.113.0/24 ~all"}
    monkeypatch.setattr(dns_checks, "_spf_record", lambda name: zone.get(name))
    r = client.post("/api/tools/spf-tree", json={"record": "v=spf1 include:_spf.google.com mx include:missing.net -all"})
    body = r.json()
    assert r.status_code == 200 and body["lookups"] == 4 and body["limit"] == 10
    google = body["tree"][0]
    assert google["children"][0]["term"] == "include:_netblocks.google.com"
    assert body["tree"][2]["error"] == "no single SPF record"
    assert client.post("/api/tools/spf-tree", json={"record": "hello world"}).status_code == 400
    assert client.post("/api/tools/spf-tree", json={"record": "v=spf1 include:bad_host!x.com -all"}).status_code == 400


# ------------------------------------------------------------------ report
def test_dnssec_split(monkeypatch):
    have = set()

    def resolve(name, rtype, lifetime=None):
        if rtype in have:
            return ["x"]
        raise dns.resolver.NoAnswer()
    monkeypatch.setattr(dns_checks._resolver, "resolve", resolve)
    monkeypatch.setattr(dns.resolver, "zone_for_name", lambda name, resolver=None, lifetime=None: dns.name.from_text(name))
    r = dns_checks.check_dnssec("x.com")
    assert (r["score"], r["signed_at_nameservers"], r["ds_at_registrar"]) == (0, False, False)
    have.add("DNSKEY")
    r = dns_checks.check_dnssec("x.com")
    assert (r["status"], r["score"], r["signed_at_nameservers"], r["ds_at_registrar"]) == ("warn", 2, True, False)
    have.add("DS")
    r = dns_checks.check_dnssec("x.com")
    assert (r["status"], r["signed_at_nameservers"], r["ds_at_registrar"]) == ("pass", True, True)


def test_observations_sorted_by_severity():
    rows = observations.build([
        {"key": "bimi", "title": "BIMI", "status": "warn", "issues": ["No BIMI."], "fixes": ["Publish BIMI."]},
        {"key": "spf", "title": "SPF", "status": "warn", "issues": ["~all"], "fixes": ["Use -all."]},
        {"key": "dmarc", "title": "DMARC", "status": "fail", "issues": ["None."], "fixes": ["Add DMARC."]},
        {"key": "mx", "title": "MX", "status": "pass"},
    ])
    assert [(r["risk"], r["severity"]) for r in rows] == [("DMARC", "High"), ("SPF", "Medium"), ("BIMI", "Low")]
    assert rows[0]["impact"].startswith("Mail that fails authentication")
    assert rows[1]["fix"] == "Use -all."
