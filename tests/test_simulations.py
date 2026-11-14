"""Phishing simulations: safeguards, sending, click and report tracking."""
from email import message_from_bytes, policy

import pytest
from fastapi.testclient import TestClient

from app import mailer, models, simulations as sims
from app.config import settings
from app.main import app
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)

H = {"X-CSRF-Token": "test-csrf"}
SMTP = {"host": "smtp.acme.com", "port": 587, "security": "starttls", "from_address": "it@acme.com"}


@pytest.fixture()
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "deliver", lambda cfg, msg: sent.append(msg))
    return sent


@pytest.fixture()
def dns(monkeypatch):
    records = {}
    monkeypatch.setattr(sims, "_txt", lambda name: records.get(name, []))
    return records


def _owner(db, smtp=True):
    owner = make_user(db, "boss@acme.com", company="Acme")
    if smtp:
        owner.tenant.smtp = dict(SMTP)
        db.commit()
    return owner


def _launch(c, recipients="jane@acme.com\nbob@acme.com", **kw):
    body = {"name": "Q1 test", "template": "password_expiry", "recipients": recipients, "authorized": True, **kw}
    return c.post("/api/simulations", json=body, headers=H)


def test_domain_proof_by_dns_or_cloud(db, dns):
    owner = _owner(db)
    c = TestClient(app)
    login_as(c, owner)
    r = c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H)
    assert r.status_code == 400 and "_phishlens-sim.acme.com" in r.json()["detail"]
    dns["_phishlens-sim.acme.com"] = [sims.verify_value(owner.tenant_id)]
    assert c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H).json()["how"] == "dns"
    # Another company's value doesn't count.
    dns["_phishlens-sim.other.com"] = [sims.verify_value("someone-else")]
    assert c.post("/api/simulations/domains", json={"domain": "other.com"}, headers=H).status_code == 400
    owner.tenant.posture = {"m365": {"result": {"domains": ["acme.co.uk"]}}}
    db.commit()
    assert c.post("/api/simulations/domains", json={"domain": "acme.co.uk"}, headers=H).json()["how"] == "cloud"
    got = c.get("/api/simulations").json()
    assert [d["domain"] for d in got["domains"]] == ["acme.co.uk", "acme.com"]
    assert got["mail_server"] is True


def test_launch_safeguards(db, dns, outbox):
    owner = _owner(db, smtp=False)
    admin = make_user(db, "admin@acme.com", role="admin", tenant=owner.tenant)
    dns["_phishlens-sim.acme.com"] = [sims.verify_value(owner.tenant_id)]
    c = TestClient(app)
    login_as(c, owner)
    c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H)
    assert "mail server" in _launch(c).json()["detail"]  # never the service's own mail server
    owner.tenant.smtp = dict(SMTP)
    db.commit()
    assert _launch(c, authorized=False).status_code == 400
    assert _launch(c, template="bank_login").status_code == 400
    r = _launch(c, recipients="jane@acme.com\nceo@gmail.com")
    assert r.status_code == 400 and "gmail.com" in r.json()["detail"]
    too_many = "\n".join(f"u{i}@acme.com" for i in range(sims.MAX_RECIPIENTS + 1))
    assert _launch(c, recipients=too_many).status_code == 400
    a = TestClient(app)
    login_as(a, admin)
    assert _launch(a).status_code == 403  # owners only
    # A removed TXT record stops new tests.
    dns.clear()
    assert _launch(c).status_code == 400
    db.refresh(owner.tenant)
    assert not owner.tenant.sim_domains
    assert outbox == []


def test_send_click_and_report(db, dns, outbox):
    owner = _owner(db)
    dns["_phishlens-sim.acme.com"] = [sims.verify_value(owner.tenant_id)]
    c = TestClient(app)
    login_as(c, owner)
    c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H)
    r = _launch(c, recipients="Jane@Acme.com, bob@sales.acme.com; jane@acme.com")
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert len(outbox) == 2  # sent by the background task, duplicates removed
    msg = outbox[0]
    assert msg["From"] == "IT Service Desk <it@acme.com>" and msg[sims.HEADER] == cid
    text = msg.get_body(("plain",)).get_content()
    token = sims.TOKEN_RE.search(text).group(1)
    assert sims.link_for(token) in text
    assert "<form" not in msg.get_body(("html",)).get_content()
    camp = c.get("/api/simulations").json()["campaigns"][0]
    assert camp["sent"] == 2 and camp["status"] == "sent" and camp["authorized_by"] == "boss@acme.com"

    anon = TestClient(app)
    page = anon.get(f"/s/{token}")
    assert page.status_code == 200 and "phishing test" in page.text.lower()
    assert "type=\"password\"" not in page.text and "<form" not in page.text
    assert "form-action 'none'" in page.headers["content-security-policy"]
    # A link scanner fetching the page doesn't count as a click; the page's script does.
    assert c.get(f"/api/simulations/{cid}").json()["people"][0]["clicked_at"] is None
    assert anon.post(f"/s/{token}/seen").status_code == 204
    assert anon.get("/s/not-a-real-token-at-all-xxxx").status_code == 404

    # Reporting the email through the report inbox counts as reported, no incident opened.
    eml = msg.as_bytes()
    rep = c.post("/api/phish-reports", content=eml, headers={"Content-Type": "message/rfc822", **H}).json()
    assert rep["simulation"] is True
    assert db.query(models.PhishReport).count() == 0
    people = {p["email"]: p for p in c.get(f"/api/simulations/{cid}").json()["people"]}
    jane = people[message_from_bytes(eml, policy=policy.default)["To"]]
    assert jane["clicked_at"] and jane["reported_at"]
    camp = c.get("/api/simulations").json()["campaigns"][0]
    assert camp["click_rate"] == 50 and camp["report_rate"] == 50


def test_report_from_another_company_is_not_matched(db, dns, outbox, monkeypatch):
    monkeypatch.setattr("app.phish_reports.triage", lambda parsed, check_url=None: {
        "verdict": "suspicious", "score": 30, "header": {}, "links": []})
    owner = _owner(db)
    dns["_phishlens-sim.acme.com"] = [sims.verify_value(owner.tenant_id)]
    c = TestClient(app)
    login_as(c, owner)
    c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H)
    _launch(c, recipients="jane@acme.com")
    eml = outbox[0].as_bytes()
    other = make_user(db, "eve@other.com", company="Other")
    o = TestClient(app)
    login_as(o, other)
    res = o.post("/api/phish-reports", content=eml, headers={"Content-Type": "message/rfc822", **H})
    assert res.status_code == 201 and "simulation" not in res.json()


def test_plan_gate_and_delete(db, dns, outbox, monkeypatch):
    owner = _owner(db)
    dns["_phishlens-sim.acme.com"] = [sims.verify_value(owner.tenant_id)]
    c = TestClient(app)
    login_as(c, owner)
    c.post("/api/simulations/domains", json={"domain": "acme.com"}, headers=H)
    cid = _launch(c, recipients="jane@acme.com").json()["id"]
    assert c.delete(f"/api/simulations/{cid}", headers=H).json() == {"ok": True}
    assert db.query(models.SimRecipient).count() == 0
    monkeypatch.setattr(settings, "PLANS_ENABLED", True)
    assert c.get("/api/simulations").status_code == 402
