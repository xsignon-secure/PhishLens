"""Nov 2026 gaps, batch 1: mailbox-provider requirements, parked domains,
undo for one-click DNS changes, bulk monitoring and "email me the fix guide"."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import dns_providers, mailer, models
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.routers import signup as signup_router
from app.scanner import compliance, dns_checks, mail_checks
from tests.conftest import admin_headers, login_as, make_user


def _c(key, status="pass", **kw):
    return {"key": key, "title": key.upper(), "status": status, "score": 0, "max_score": 0,
            "details": "", "issues": [], "fixes": [], **kw}


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda d: [
        _c("dmarc", "fail", max_score=20, fixes=["v=DMARC1; p=none"])])
    monkeypatch.setattr("app.scanner.reputation.lookup", lambda d: None)
    return TestClient(app)


# ------------------------------------------------------------------ compliance
def test_provider_requirements_follow_the_checks():
    good = [_c("spf"), _c("dkim", bits=2048), _c("dmarc", record="v=DMARC1; p=none"), _c("ptr"), _c("smtp-tls")]
    out = {p["key"]: p for p in compliance.build(good)}
    assert set(out) == {"gmail", "yahoo", "microsoft"}
    assert all(p["status"] == "pass" for p in out.values())
    manual = [r for r in out["gmail"]["rules"] if r["status"] == "manual"]
    assert {r["key"] for r in manual} == {"alignment", "unsubscribe", "spam_rate"}

    bad = [_c("spf"), _c("dkim", "fail"), _c("dmarc", "fail"), _c("ptr", "warn"), _c("smtp-tls")]
    out = {p["key"]: p for p in compliance.build(bad)}
    assert out["microsoft"]["status"] == "fail"
    rules = {r["key"]: r["status"] for r in out["gmail"]["rules"]}
    assert rules["spf_or_dkim"] == "pass" and rules["dkim"] == "fail" and rules["dmarc"] == "fail"
    weak = compliance.rules([_c("dkim", bits=512)])
    assert weak["dkim"]["status"] == "fail"


def test_free_report_includes_provider_requirements(client):
    body = client.post("/api/scans/public", json={"domain": "x.com"}).json()
    assert body["result"]["solutions_locked"]
    assert [p["key"] for p in body["result"]["compliance"]] == ["gmail", "yahoo", "microsoft"]


# ------------------------------------------------------------------ parked domains
def test_parked_domain_needs_null_mx_spf_minus_all_and_dmarc_reject(monkeypatch):
    txt = {}
    monkeypatch.setattr(dns_checks, "_txt", lambda name: txt.get(name, []))
    monkeypatch.setattr(mail_checks, "_mx_hosts", lambda d: ["mx.x.com"])
    assert mail_checks.check_parked("x.com")["status"] == "pass"

    monkeypatch.setattr(mail_checks, "_mx_hosts", lambda d: [])
    r = mail_checks.check_parked("x.com")
    assert r["status"] == "warn" and r["max_score"] == 0
    assert "v=spf1 -all" in r["fixes"] and "v=DMARC1; p=reject; sp=reject" in r["fixes"]
    assert any("null MX" in f for f in r["fixes"])

    monkeypatch.setattr(mail_checks, "_mx_hosts", lambda d: None)  # null MX
    txt.update({"x.com": ["v=spf1 -all"], "_dmarc.x.com": ["v=DMARC1; p=reject"]})
    assert mail_checks.check_parked("x.com")["status"] == "pass"


# ------------------------------------------------------------------ DNS undo
def _cf(store):
    def handler(request: httpx.Request):
        path, m = request.url.path, request.method
        if path.endswith("/user/tokens/verify"):
            return httpx.Response(200, json={"success": True, "result": {"status": "active"}})
        if path.endswith("/zones"):
            name = request.url.params["name"]
            return httpx.Response(200, json={"success": True,
                                             "result": [{"id": "z1", "name": name}] if name == "x.com" else []})
        if path.endswith("/dns_records") and m == "GET":
            p = request.url.params
            return httpx.Response(200, json={"success": True, "result": [
                r for r in store.values() if r["name"] == p["name"] and r["type"] == p["type"]]})
        if path.endswith("/dns_records") and m == "POST":
            rid = f"r{len(store) + 10}"
            store[rid] = {"id": rid, **json.loads(request.content)}
            return httpx.Response(200, json={"success": True, "result": store[rid]})
        rid = path.rsplit("/", 1)[1]
        if m == "PUT":
            store[rid] = {"id": rid, **json.loads(request.content)}
        elif m == "DELETE":
            store.pop(rid, None)
        return httpx.Response(200, json={"success": True, "result": {}})
    return httpx.MockTransport(handler)


@pytest.fixture()
def cf_store(monkeypatch):
    store = {"r1": {"id": "r1", "name": "x.com", "type": "TXT", "content": "google-site-verification=abc"},
             "r2": {"id": "r2", "name": "x.com", "type": "TXT", "content": "v=spf1 include:_spf.google.com ~all"}}
    real = dns_providers.Cloudflare
    monkeypatch.setattr(dns_providers, "Cloudflare", lambda token, transport=None: real(token, _cf(store)))
    return store


def _txts(store, name):
    return sorted(r["content"] for r in store.values() if r["name"] == name and r["type"] == "TXT")


def test_one_click_change_can_be_undone(client, db, cf_store):
    h = admin_headers(client)
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    assert client.put("/api/team/cloudflare", json={"token": "t" * 40}, headers=h).status_code == 200
    r = client.post("/api/dns/apply", json={"name": "x.com", "type": "TXT", "value": "v=spf1 include:_spf.google.com -all"},
                    headers=h).json()
    assert r["result"] == "updated" and r["change_id"]
    d = client.post("/api/dns/apply", json={"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=none"},
                    headers=h).json()
    applied = client.get("/api/dns/applied", headers=h).json()
    assert [a["name"] for a in applied] == ["_dmarc.x.com", "x.com"]
    assert applied[1]["previous"] == ["v=spf1 include:_spf.google.com ~all"]

    undo = client.post(f"/api/dns/applied/{r['change_id']}/rollback", headers=h)
    assert undo.status_code == 200, undo.text
    # The old SPF is back and the unrelated verification record was never touched.
    assert _txts(cf_store, "x.com") == ["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"]
    assert client.post(f"/api/dns/applied/{r['change_id']}/rollback", headers=h).status_code == 409

    # A record that didn't exist before is removed on undo.
    assert client.post(f"/api/dns/applied/{d['change_id']}/rollback", headers=h).status_code == 200
    assert _txts(cf_store, "_dmarc.x.com") == []


def test_undo_refuses_when_the_record_changed_again(client, db, cf_store):
    h = admin_headers(client)
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    client.put("/api/team/cloudflare", json={"token": "t" * 40}, headers=h)
    r = client.post("/api/dns/apply", json={"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=none"},
                    headers=h).json()
    rec = next(v for v in cf_store.values() if v["name"] == "_dmarc.x.com")
    rec["content"] = "v=DMARC1; p=reject"  # someone edited it in the DNS host since
    assert client.post(f"/api/dns/applied/{r['change_id']}/rollback", headers=h).status_code == 409
    assert _txts(cf_store, "_dmarc.x.com") == ["v=DMARC1; p=reject"]


def test_other_companies_cannot_undo_or_list_changes(client, db, cf_store):
    h = admin_headers(client)
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    client.put("/api/team/cloudflare", json={"token": "t" * 40}, headers=h)
    r = client.post("/api/dns/apply", json={"name": "_dmarc.x.com", "type": "TXT", "value": "v=DMARC1; p=none"},
                    headers=h).json()
    other = TestClient(app)
    b = make_user(db, "b@other.com", company="Other")
    h2 = {"Authorization": f"Bearer {login_as(other, b, keep_cookies=False)['access_token']}"}
    assert other.get("/api/dns/applied", headers=h2).json() == []
    assert other.post(f"/api/dns/applied/{r['change_id']}/rollback", headers=h2).status_code == 404


# ------------------------------------------------------------------ bulk monitoring
def test_bulk_add_monitors_skips_duplicates_invalid_and_over_limit(client, db, monkeypatch):
    h = admin_headers(client)
    client.post("/api/monitors", json={"domain": "a.com"}, headers=h)
    monkeypatch.setattr(settings, "MAX_MONITORS_PER_TEAM", 3)
    r = client.post("/api/monitors/bulk", json={"domains": "a.com\nb.com, c.com\nnot a domain!!\nb.com d.com"},
                    headers=h)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["added"] == ["b.com", "c.com"]
    reasons = {s["domain"]: s["reason"] for s in body["skipped"]}
    assert reasons["a.com"] == "already monitored" and "limit" in reasons["d.com"]
    monitors = {m["domain"]: m for m in client.get("/api/monitors", headers=h).json()}
    assert set(monitors) == {"a.com", "b.com", "c.com"}
    assert monitors["b.com"]["last_score"] is not None  # baseline scan ran in the background


def test_bulk_add_limits_list_size(client, db):
    h = admin_headers(client)
    many = "\n".join(f"d{i}.com" for i in range(201))
    assert client.post("/api/monitors/bulk", json={"domains": many}, headers=h).status_code == 400


# ------------------------------------------------------------------ email me the fix guide
def test_email_me_the_fix_guide_creates_account_and_sends_guide(client, db, monkeypatch):
    sent = []
    monkeypatch.setattr(settings, "SIGNUP_ENABLED", True)
    monkeypatch.setattr(mailer, "is_configured", lambda: True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.server.example")
    monkeypatch.setattr(settings, "SMTP_FROM", "noreply@server.example")
    monkeypatch.setattr(mailer, "deliver", lambda cfg, msg: sent.append(msg))
    monkeypatch.setattr(signup_router, "mail_domain_ok", lambda d: True)
    scan_id = client.post("/api/scans/public", json={"domain": "x.com"}).json()["id"]
    r = client.post("/api/auth/signup", json={"email": "ana@acme.example", "company": "Acme",
                                              "accept_terms": True, "scan_id": scan_id})
    assert r.status_code == 202, r.text
    subjects = sorted(m["Subject"] for m in sent)
    assert any(x.endswith("Fix guide for x.com") for x in subjects) and len(sent) == 2
    guide = next(m for m in sent if m["Subject"].endswith("Fix guide for x.com"))
    names = [p.get_filename() for p in guide.iter_attachments()]
    assert names and names[0].endswith("-fix-guide.pdf")
    # An address that already has an account gets nothing new.
    sent.clear()
    client.post("/api/auth/signup", json={"email": "ana@acme.example", "company": "Acme",
                                          "accept_terms": True, "scan_id": scan_id})
    assert not sent
