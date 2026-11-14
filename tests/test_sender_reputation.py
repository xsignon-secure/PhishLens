"""Sender reputation from Google Postmaster Tools and Microsoft SNDS."""
import json
import urllib.parse
from datetime import date

import httpx
import pytest
from fastapi.testclient import TestClient

from app import crypto, mailer, models, sender_reputation as rep
from app.config import settings
from app.main import app
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)

SNDS_CSV = ("203.0.113.5,11/12/2026 1:00 AM,11/12/2026 11:00 PM,1200,1200,1150,GREEN,< 0.1%,,,0,mail.acme.com,,\n"
            "203.0.113.6,11/12/2026 1:00 AM,11/12/2026 11:00 PM,900,900,880,RED,2.5%,,,14,mx2.acme.com,,\n")
STATUS_CSV = "203.0.113.6,203.0.113.6,Yes,Blocked due to user complaints or other evidence of spamming\n"


def google_handler(reputation="HIGH", spam=0.0005):
    def handler(request: httpx.Request):
        u = str(request.url)
        if u.startswith(rep.GOOGLE_TOKEN):
            body = urllib.parse.parse_qs(request.content.decode())
            if body["grant_type"] == ["refresh_token"]:
                return httpx.Response(200, json={"access_token": "at"})
            return httpx.Response(200, json={"refresh_token": "rt-1", "access_token": "at", "scope": rep.SCOPE + " email",
                                             "id_token": "e30.eyJlbWFpbCI6ICJpdEBhY21lLmNvbSJ9.sig"})
        if u.startswith(rep.POSTMASTER + "/domains?"):
            assert request.headers["Authorization"] == "Bearer at"
            return httpx.Response(200, json={"domains": [{"name": "domains/acme.com"}]})
        if "/trafficStats" in u:
            return httpx.Response(200, json={"trafficStats": [
                {"name": "domains/acme.com/trafficStats/20261111", "domainReputation": "HIGH", "userReportedSpamRatio": 0.0001},
                {"name": "domains/acme.com/trafficStats/20261112", "domainReputation": reputation,
                 "userReportedSpamRatio": spam, "spfSuccessRatio": 1, "dkimSuccessRatio": 0.98, "dmarcSuccessRatio": 0.97,
                 "ipReputations": [{"reputation": "HIGH", "ipCount": "2"}]}]})
        if u.startswith(rep.SNDS_DATA):
            return httpx.Response(200, text=SNDS_CSV)
        if u.startswith(rep.SNDS_STATUS):
            return httpx.Response(200, text=STATUS_CSV)
        if u.startswith(rep.GOOGLE_REVOKE):
            return httpx.Response(200)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


@pytest.fixture()
def tenant(db, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "GOOGLE_POSTMASTER_CLIENT_ID", "cid")
    monkeypatch.setattr(settings, "GOOGLE_POSTMASTER_CLIENT_SECRET", "secret")
    owner = make_user(db, "boss@acme.com", company="Acme")
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="acme.com"))
    db.commit()
    return owner


def test_google_flow_and_stats(tenant, db):  # noqa: F811
    t = db.get(models.Tenant, tenant.tenant_id)
    url, cookie = rep.google_start(t, tenant)
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["scope"][0].startswith(rep.SCOPE) and q["access_type"] == ["offline"] and q["code_challenge_method"] == ["S256"]
    state = rep.read_state(cookie)
    assert state["state"] == q["state"][0]
    assert rep.google_finish(db, t, "code", state, transport=google_handler()) == "it@acme.com"
    assert t.postmaster_token != "rt-1" and crypto.decrypt(t.postmaster_token) == "rt-1"
    stats = rep.fetch_google(t, transport=google_handler(), today=date(2026, 11, 13))
    last = stats["acme.com"][-1]
    assert last["day"] == "2026-11-12" and last["domain_reputation"] == "HIGH" and last["dkim"] == 0.98
    assert last["ip_reputation"] == {"HIGH": 2}


def test_alerts_once_for_bad_reputation_and_spam(tenant, db, monkeypatch):  # noqa: F811
    t = db.get(models.Tenant, tenant.tenant_id)
    t.postmaster_token = crypto.encrypt("rt-1")
    db.commit()
    mails = []
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, body, **k: mails.append(body) or True)
    bad = google_handler(reputation="LOW", spam=0.005)
    rep.refresh(db, t, force=True, transport=bad)
    assert len(mails) == 1 and "LOW" in mails[0] and "0.50%" in mails[0]
    kinds = [a.kind for a in db.query(models.Alert).all()]
    assert kinds == ["sender_reputation", "sender_reputation"]
    rep.refresh(db, t, force=True, transport=bad)
    assert len(mails) == 1  # same problem, no new email
    rep.refresh(db, t, force=True, transport=google_handler())  # recovered
    rep.refresh(db, t, force=True, transport=bad)  # and back again: alert again
    assert len(mails) == 2
    # Not forced and fresh: nothing fetched.
    assert rep.refresh(db, t, transport=httpx.MockTransport(lambda r: pytest.fail("fetched"))) is not None


def test_snds(tenant, db, monkeypatch):  # noqa: F811
    t = db.get(models.Tenant, tenant.tenant_id)
    mails = []
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, body, **k: mails.append(body) or True)
    rep.set_snds_key(db, t, "abcd-1234")
    assert crypto.decrypt(t.snds_key) == "abcd-1234"
    out = rep.refresh(db, t, force=True, transport=google_handler())
    rows = out["snds"]["rows"]
    assert [r["filter"] for r in rows] == ["GREEN", "RED"] and rows[1]["complaint_rate"] == 0.025 and rows[1]["trap_hits"] == 14
    assert rows[0]["complaint_rate"] == 0.001
    assert "203.0.113.6" in mails[0] and "blocking" in mails[0]
    assert not db.query(models.Alert).all()  # IP problems have no domain monitor: email only
    rep.set_snds_key(db, t, "")
    assert t.snds_key is None and "snds" not in t.sender_rep


def test_api(tenant, db, monkeypatch):  # noqa: F811
    c = TestClient(app)
    oh = {"Authorization": f"Bearer {login_as(c, tenant, keep_cookies=False)['access_token']}"}
    member = make_user(db, "staff@acme.com", role="member", tenant=tenant.tenant, mfa=False)
    mh = {"Authorization": f"Bearer {login_as(c, member, keep_cookies=False)['access_token']}"}
    d = c.get("/api/reputation", headers=mh).json()
    assert d["google"] == {"configured": True, "connected": False, "account": None, "domains": {}}
    assert c.post("/api/reputation/google/connect", headers=mh).status_code == 403
    r = c.post("/api/reputation/google/connect", headers=oh)
    assert r.status_code == 200 and r.json()["url"].startswith(rep.GOOGLE_AUTH)
    assert "postmaster_state" in r.headers["set-cookie"]
    assert c.put("/api/reputation/snds", headers=oh, json={"key": "bad key!"}).status_code == 422
    monkeypatch.setattr(rep, "refresh", lambda db, t, **k: None)
    d = c.put("/api/reputation/snds", headers=oh, json={"key": "abcd-1234"}).json()
    assert d["snds"]["connected"] is True and "abcd" not in json.dumps(d)


def test_callback_checks_state_and_user(tenant, db, monkeypatch):  # noqa: F811
    c = TestClient(app)
    login_as(c, tenant)
    t = db.get(models.Tenant, tenant.tenant_id)
    url, cookie = rep.google_start(t, tenant)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
    c.cookies.set("postmaster_state", cookie, domain="testserver.local", path="/reputation/google/callback")
    r = c.get("/reputation/google/callback?code=x&state=wrong", follow_redirects=False)
    assert "reputation=expired" in r.headers["location"]
    monkeypatch.setattr(rep, "google_finish", lambda db, t, code, data: "it@acme.com")
    monkeypatch.setattr(rep, "refresh", lambda db, t, **k: None)
    c.cookies.set("postmaster_state", cookie, domain="testserver.local", path="/reputation/google/callback")
    r = c.get(f"/reputation/google/callback?code=x&state={state}", follow_redirects=False)
    assert "reputation=connected" in r.headers["location"]


def test_not_configured(db, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "GOOGLE_POSTMASTER_CLIENT_ID", "")
    u = make_user(db, "a@b.com")
    with pytest.raises(rep.ReputationError):
        rep.google_start(u.tenant, u)
