"""Phishing report inbox (triage of reported emails) and takedown drafts."""
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app import models, phish_reports
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import login_as, make_user


def _phish() -> bytes:
    m = EmailMessage()
    m["From"] = '"PayPal Support" <service@paypa1-secure.top>'
    m["To"] = "staff@acme.com"
    m["Subject"] = "Your account is suspended"
    m["Reply-To"] = "collect@evil.example"
    m["Authentication-Results"] = "mx.acme.com; spf=fail smtp.mailfrom=paypa1-secure.top; dkim=none; dmarc=fail header.from=paypa1-secure.top"
    m.set_content("Verify now: https://paypa1-secure.top/login?id=1 or https://paypa1-secure.top/other")
    m.add_alternative('<p>Hi</p><a href="https://paypa1-secure.top/login?id=1&amp;x=2">Verify</a>'
                      '<a href="https://www.acme.com/help">Help</a>', subtype="html")
    return bytes(m)


def _forwarded(inner: bytes) -> bytes:
    outer = EmailMessage()
    outer["From"] = "staff@acme.com"
    outer["Subject"] = "Fwd: suspicious"
    outer.set_content("Looks fishy, see attached. https://should-not-be-checked.example")
    outer.add_attachment(inner, maintype="message", subtype="rfc822")
    return bytes(outer)


def fake_check(url):
    if "paypa1" in url:
        return {"url": url, "domain": "paypa1-secure.top", "verdict": "dangerous", "risk": 100,
                "signals": [{"points": 30, "text": "Brand name paypal on an unrelated domain"}],
                "feeds": [{"source": "OpenPhish", "listed": True}]}
    return {"url": url, "domain": "acme.com", "verdict": "no known threat", "risk": 0, "signals": [], "feeds": []}


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def setup(db, monkeypatch):
    monkeypatch.setattr("app.url_check.check", fake_check)
    monkeypatch.setattr(phish_reports.triage, "__defaults__", (fake_check,))
    owner = make_user(db, "boss@acme.com", company="Acme Corp")
    member = make_user(db, "staff@acme.com", role="member", tenant=owner.tenant, mfa=False)
    c = TestClient(app)
    oh = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    mh = {"Authorization": f"Bearer {login_as(c, member, keep_cookies=False)['access_token']}"}
    return owner, c, oh, mh


def test_parse_finds_links_in_forwarded_attachment():
    p = phish_reports.parse(_forwarded(_phish()))
    assert p["subject"] == "Your account is suspended" and "paypa1-secure.top" in p["from"]
    assert "https://paypa1-secure.top/login?id=1&x=2" in p["urls"] and "https://www.acme.com/help" in p["urls"]
    assert not any("should-not-be-checked" in u for u in p["urls"])
    outer = EmailMessage()
    outer["Subject"] = "Fwd"
    outer.set_content("see attached")
    from email import message_from_bytes, policy
    outer.add_attachment(message_from_bytes(_phish(), policy=policy.default))
    assert phish_reports.parse(bytes(outer))["subject"] == "Your account is suspended"
    with pytest.raises(phish_reports.ReportError):
        phish_reports.parse(b"")


def test_member_reports_and_admin_triages(setup, db):
    owner, c, oh, mh = setup
    r = c.post("/api/phish-reports", headers=mh, content=_forwarded(_phish()))
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["verdict"] == "dangerous" and rep["reported_by"] == "staff@acme.com"
    assert {x["domain"] for x in rep["links"]} == {"paypa1-secure.top", "acme.com"}  # one check per domain
    assert rep["header"]["level"] == "fail"
    row = db.query(models.PhishReport).one()
    assert "Verify now" not in str(row.header) + str(row.links)  # no body kept
    assert c.patch(f"/api/phish-reports/{rep['id']}", headers=mh, json={"status": "confirmed"}).status_code == 403
    assert c.patch(f"/api/phish-reports/{rep['id']}", headers=oh, json={"status": "confirmed"}).json()["status"] == "confirmed"
    assert [x["id"] for x in c.get("/api/phish-reports", headers=mh).json()] == [rep["id"]]
    # Other companies can't see it.
    other = make_user(db, "x@other.com", company="Other")
    xh = {"Authorization": f"Bearer {login_as(c, other, keep_cookies=False)['access_token']}"}
    assert c.get("/api/phish-reports", headers=xh).json() == []
    assert c.get(f"/api/phish-reports/{rep['id']}", headers=xh).status_code == 404


def test_takedown_draft(setup, monkeypatch):
    owner, c, oh, mh = setup
    rep = c.post("/api/phish-reports", headers=mh, content=_phish()).json()

    def rdap(url):
        if "/domain/" in url:
            return {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Names Inc"]]],
                                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                                      ["email", {}, "text", "Abuse@CheapNames.example"]]]}]}]}
        return {"name": "HOSTNET-1", "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
            ["email", {}, "text", "abuse@hostnet.example"]]]}]}
    real = phish_reports.takedown
    monkeypatch.setattr(phish_reports, "takedown", lambda *a, **k: real(*a, rdap=rdap, resolve=lambda n: ["203.0.113.7"]))
    assert c.post("/api/phish-reports/takedown", headers=mh, json={"domain": "paypa1-secure.top"}).status_code == 403
    d = c.post("/api/phish-reports/takedown", headers=oh,
               json={"domain": "paypa1-secure.top", "url": "https://paypa1-secure.top/login", "report_id": rep["id"]}).json()
    assert d["to"] == ["abuse@cheapnames.example", "abuse@hostnet.example"]
    assert d["registrar"]["name"] == "Cheap Names Inc" and d["hosting"]["name"] == "HOSTNET-1" and d["ip"] == "203.0.113.7"
    assert "impersonating Acme Corp" in d["subject"]
    assert "Listed by OpenPhish" in d["body"] and "Your account is suspended" in d["body"]
