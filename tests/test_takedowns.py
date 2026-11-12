"""Takedown tracking (draft -> sent -> down) and AI triage of reported phish."""
from datetime import datetime, timedelta

import dns.resolver
import httpx
import pytest

from app import mailer, models, phish_reports, takedowns
from app.config import settings
from tests.conftest import login_as, make_user
from tests.test_phish_reports import _phish, db, fake_check, setup  # noqa: F401  (fixtures)

DRAFT = {"domain": "paypa1-secure.top", "ip": "203.0.113.7",
         "registrar": {"name": "Cheap Names Inc", "abuse": ["abuse@cheapnames.example"]},
         "hosting": {"name": "HOSTNET-1", "abuse": ["abuse@hostnet.example"]},
         "to": ["abuse@cheapnames.example", "abuse@hostnet.example"],
         "subject": "Phishing report: paypa1-secure.top impersonating Acme Corp", "body": "Hello", "also": []}


@pytest.fixture()
def env(setup, monkeypatch):
    calls = []
    monkeypatch.setattr(phish_reports, "takedown", lambda domain, *a, **k: calls.append(domain) or {**DRAFT, "domain": domain})
    sent = []
    monkeypatch.setattr(mailer, "config_for", lambda tenant: {"host": "smtp.acme.example", "from_address": "it@acme.com",
                                                              "from_name": None, "port": 587, "security": "starttls"})
    monkeypatch.setattr(mailer, "deliver", lambda cfg, msg: sent.append(msg))
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "AI_PROVIDER", "")
    return (*setup, calls, sent)


def test_dangerous_report_opens_a_draft_by_itself(env, db):
    owner, c, oh, mh, calls, sent = env
    rep = c.post("/api/phish-reports", headers=mh, content=_phish()).json()
    assert rep["takedowns_opened"] == ["paypa1-secure.top"] and rep["ai"] is None
    rows = c.get("/api/phish-reports/takedowns", headers=mh).json()
    assert len(rows) == 1 and rows[0]["status"] == "draft" and rows[0]["auto"] and rows[0]["report_id"] == rep["id"]
    assert not sent  # drafts are never sent without a person
    # A second report of the same site reuses the open takedown.
    c.post("/api/phish-reports", headers=mh, content=_phish())
    assert len(c.get("/api/phish-reports/takedowns", headers=mh).json()) == 1


def test_own_domains_never_get_a_takedown(env, db):
    owner, c, oh, mh, calls, sent = env
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="paypa1-secure.top"))
    db.commit()
    rep = c.post("/api/phish-reports", headers=mh, content=_phish()).json()
    assert rep["takedowns_opened"] == []


def test_send_with_netcraft_then_tracked_until_down(env, db, monkeypatch):
    owner, c, oh, mh, calls, sent = env
    t = c.post("/api/phish-reports/takedowns", headers=oh,
               json={"domain": "paypa1-secure.top", "url": "https://paypa1-secure.top/login"}).json()
    assert c.post(f"/api/phish-reports/takedowns/{t['id']}/send", headers=mh, json={}).status_code == 403
    nc = []

    def netcraft(email, url, reason, transport=None):
        nc.append((email, url))
        return True, "Netcraft submission abc"
    monkeypatch.setattr(takedowns, "_netcraft", netcraft)
    t = c.post(f"/api/phish-reports/takedowns/{t['id']}/send", headers=oh, json={"netcraft": True, "apwg": True}).json()
    assert t["status"] == "sent" and t["sent_at"]
    msg = sent[0]
    assert "abuse@cheapnames.example" in msg["To"] and takedowns.APWG in msg["To"]
    assert msg["Reply-To"] == "boss@acme.com" and not msg["Subject"].startswith("[")
    assert nc == [("boss@acme.com", "https://paypa1-secure.top/login")]
    assert [s["ok"] for s in t["submissions"]] == [True, True]

    # Daily recheck: still live -> nothing; after 3 days -> one reminder; then down -> told.
    row = db.get(models.Takedown, t["id"])
    mails = []
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, body, **k: mails.append(subject) or True)
    live = lambda d, u: {"live": True, "reason": "Still online (HTTP 200)."}
    assert takedowns.recheck_all(db, check=live)["reminded"] == 0
    later = datetime.utcnow() + timedelta(days=3, hours=1)
    assert takedowns.recheck_all(db, check=live, now=later)["reminded"] == 1
    assert takedowns.recheck_all(db, check=live, now=later + timedelta(days=1))["reminded"] == 0
    gone = lambda d, u: {"live": False, "reason": "The domain no longer exists (suspended or deleted)."}
    assert takedowns.recheck_all(db, check=gone, now=later + timedelta(days=2))["down"] == 1
    db.refresh(row)
    assert row.status == "down" and row.down_at and row.live is False
    assert mails == ["Phishing site still online: paypa1-secure.top", "Phishing site taken down: paypa1-secure.top"]


def test_send_without_mail_server_or_addresses_fails_cleanly(env, db, monkeypatch):
    owner, c, oh, mh, calls, sent = env
    t = c.post("/api/phish-reports/takedowns", headers=oh, json={"domain": "paypa1-secure.top"}).json()
    monkeypatch.setattr(mailer, "config_for", lambda tenant: None)
    r = c.post(f"/api/phish-reports/takedowns/{t['id']}/send", headers=oh, json={})
    assert r.status_code == 400 and "email server" in r.json()["detail"]
    # Sent from their own mail app instead.
    t = c.patch(f"/api/phish-reports/takedowns/{t['id']}", headers=oh, json={"status": "sent"}).json()
    assert t["status"] == "sent" and "own mail" in t["submissions"][0]["detail"]
    t = c.patch(f"/api/phish-reports/takedowns/{t['id']}", headers=oh, json={"status": "closed"}).json()
    assert t["status"] == "closed"
    r = c.post(f"/api/phish-reports/takedowns/{t['id']}/send", headers=oh, json={})
    assert r.status_code == 400


def test_takedowns_are_per_company(env, db):
    owner, c, oh, mh, calls, sent = env
    t = c.post("/api/phish-reports/takedowns", headers=oh, json={"domain": "paypa1-secure.top"}).json()
    other = make_user(db, "x@other.com", company="Other")
    xh = {"Authorization": f"Bearer {login_as(c, other, keep_cookies=False)['access_token']}"}
    assert c.get("/api/phish-reports/takedowns", headers=xh).json() == []
    assert c.post(f"/api/phish-reports/takedowns/{t['id']}/check", headers=xh).status_code == 404
    assert c.post(f"/api/phish-reports/takedowns/{t['id']}/send", headers=xh, json={}).status_code == 404


def test_check_live(monkeypatch):
    def nx(name, rtype, lifetime=None):
        raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(takedowns.dns.resolver, "resolve", nx)
    assert takedowns.check_live("gone.top")["live"] is False
    monkeypatch.setattr(takedowns.dns.resolver, "resolve", lambda *a, **k: ["203.0.113.7"])
    monkeypatch.setattr(takedowns.net, "safe_get", lambda url, timeout: httpx.Response(200))
    assert takedowns.check_live("up.top")["live"] is True
    monkeypatch.setattr(takedowns.net, "safe_get", lambda url, timeout: httpx.Response(410))
    assert takedowns.check_live("up.top")["live"] is False

    def refused(url, timeout):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(takedowns.net, "safe_get", refused)
    assert takedowns.check_live("up.top")["live"] is False


def test_netcraft_api_call():
    seen = {}

    def handler(request):
        seen["url"], seen["body"] = str(request.url), request.read()
        return httpx.Response(200, json={"message": "Successfully reported", "uuid": "u-1"})
    ok, detail = takedowns._netcraft("boss@acme.com", "https://x.top/", "Phishing", httpx.MockTransport(handler))
    assert ok and "u-1" in detail and seen["url"] == takedowns.NETCRAFT_API and b"x.top" in seen["body"]


# ------------------------------------------------------------------ AI triage
def test_ai_triage_is_stored_and_only_advises(env, db, monkeypatch):
    owner, c, oh, mh, calls, sent = env
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    prompts = []

    def complete(cfg, system, prompt, max_tokens=400):
        prompts.append(prompt)
        return 'Here you go: {"summary": "A fake PayPal login page.", "impersonates": "PayPal", ' \
               '"action": "takedown", "confidence": 93}'
    monkeypatch.setattr("app.assistant.complete", complete)
    rep = c.post("/api/phish-reports", headers=mh, content=_phish()).json()
    assert rep["ai"]["impersonates"] == "PayPal" and rep["ai"]["action"] == "takedown" and rep["ai"]["confidence"] == 93
    assert "paypa1-secure.top" in prompts[0] and "Verify now" not in prompts[0]  # no message body sent to AI
    assert c.get("/api/phish-reports", headers=mh).json()[0]["ai"]["summary"] == "A fake PayPal login page."


def test_parse_ai_is_strict():
    assert phish_reports.parse_ai("not json") is None
    d = phish_reports.parse_ai('{"summary": "x", "action": "delete all mail", "confidence": "250", "impersonates": "null"}')
    assert d == {"summary": "x", "impersonates": None, "action": "no action", "confidence": 100}


def test_ai_failure_doesnt_block_the_report(env, monkeypatch):
    owner, c, oh, mh, calls, sent = env
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")

    def boom(*a, **k):
        raise RuntimeError("down")
    monkeypatch.setattr("app.assistant.complete", boom)
    r = c.post("/api/phish-reports", headers=mh, content=_phish())
    assert r.status_code == 201 and r.json()["ai"] is None
