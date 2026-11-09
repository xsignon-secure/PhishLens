"""DMARC enforcement autopilot: steps up only when safe, steps back when real
mail fails, works through hosted DMARC or a connected DNS provider."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import autopilot, crypto, dns_providers, models
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import login_as, make_user

GOOD = {"source_ip": "209.85.220.41", "dkim": "pass", "spf": "pass", "disposition": "none",
        "dkim_auth": [{"domain": "google.com", "result": "pass"}], "spf_auth": [{"domain": "google.com"}]}
SPOOF = {"source_ip": "198.51.100.7", "dkim": "fail", "spf": "fail", "disposition": "none",
         "dkim_auth": [{"domain": "spoofer.example", "result": "fail"}], "spf_auth": [{"domain": "spoofer.example"}]}
UNSIGNED_SENDGRID = {"source_ip": "203.0.113.9", "dkim": "fail", "spf": "fail", "disposition": "none",
                     "dkim_auth": [{"domain": "sendgrid.net", "result": "pass"}], "spf_auth": [{"domain": "sendgrid.net"}]}


class FakeDns(dns_providers.Provider):
    name = "Fake"

    def __init__(self, store):
        self.store = store

    def zone_for(self, name):
        return "z", "acme.com"

    def records(self, zone_id, name, rtype):
        return [{"id": i, "content": v} for i, (n, t, v) in enumerate(self.store) if n == name and t == rtype]

    def _create(self, zone_id, name, rtype, content):
        self.store.append((name, rtype, content))

    def _update(self, zone_id, rec, name, rtype, content):
        self.store[rec["id"]] = (name, rtype, content)

    def _delete(self, zone_id, rec, name, rtype):
        self.store.pop(rec["id"])


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def setup(db, monkeypatch):
    owner = make_user(db, "boss@acme.com", company="Acme")
    owner.tenant.dns_provider, owner.tenant.dns_token = "cloudflare", crypto.encrypt("t" * 30)
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="acme.com"))
    db.commit()
    store = [("_dmarc.acme.com", "TXT", "v=DMARC1; p=none; rua=mailto:d@acme.com"),
             ("_dmarc.acme.com", "TXT", "google-site-verification=keep")]
    monkeypatch.setattr(dns_providers, "client", lambda provider, token, transport=None: FakeDns(store))
    sent = []
    monkeypatch.setattr("app.mailer.send_email", lambda to, subject, body, tenant=None, **kw: sent.append(subject))
    monkeypatch.setattr("app.mailer.team_recipients", lambda db, tid: ["boss@acme.com"])
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    return owner, store, sent, c, h


def _reports(db, tenant_id, start_days_ago, days, rows, per_day=100):
    now = datetime.utcnow()
    for i in range(days):
        begin = now - timedelta(days=start_days_ago - i)
        recs = [{**r, "count": per_day} for r in rows]
        db.add(models.DmarcReport(tenant_id=tenant_id, domain="acme.com", org_name="google.com",
                                  report_id=f"r-{start_days_ago}-{i}-{len(rows)}", date_begin=begin,
                                  date_end=begin + timedelta(hours=23), policy={"p": "none"}, records=recs,
                                  message_count=per_day * len(rows), pass_count=0))
    db.commit()


def _dmarc(store):
    return [v for n, t, v in store if n == "_dmarc.acme.com" and v.startswith("v=DMARC1")]


def test_waits_for_two_weeks_of_reports(setup, db):
    owner, store, sent, c, h = setup
    _reports(db, owner.tenant_id, 5, 5, [GOOD])
    r = c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True, "target": "reject"}).json()
    assert r["mode"] == "dns" and r["status"] == "watching" and "14 days" in r["message"]
    assert _dmarc(store) == ["v=DMARC1; p=none; rua=mailto:d@acme.com"] and not sent


def test_steps_up_through_spoofing_but_not_failing_real_senders(setup, db):
    owner, store, sent, c, h = setup
    _reports(db, owner.tenant_id, 15, 15, [GOOD, SPOOF, UNSIGNED_SENDGRID])
    r = c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True}).json()
    assert "SendGrid" in r["message"] and _dmarc(store)[0].endswith("p=none; rua=mailto:d@acme.com")
    # SendGrid fixed: newer reports only have good mail and spoofing.
    db.query(models.DmarcReport).delete()
    db.commit()
    _reports(db, owner.tenant_id, 15, 15, [GOOD, SPOOF])
    r = c.post("/api/autopilot/acme.com/check", headers=h).json()
    assert r["decision"]["action"] == "step" and r["status"] == "watching"
    assert _dmarc(store) == ["v=DMARC1; p=quarantine; rua=mailto:d@acme.com"]
    assert ("_dmarc.acme.com", "TXT", "google-site-verification=keep") in store
    assert sent == ["DMARC for acme.com moved to p=quarantine"]
    # The change is listed with what it replaced, so it can be undone.
    applied = c.get("/api/dns/applied", headers=h).json()
    assert applied[0]["previous"] == ["v=DMARC1; p=none; rua=mailto:d@acme.com"]
    # Next check holds the new stage for two weeks.
    r = c.post("/api/autopilot/acme.com/check", headers=h).json()
    assert r["decision"]["action"] == "hold" and "Holding p=quarantine" in r["message"]


def test_reaches_reject_then_done(setup, db):
    owner, store, sent, c, h = setup
    _reports(db, owner.tenant_id, 15, 15, [GOOD])
    c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True})
    ap = db.query(models.DmarcAutopilot).one()
    ap.last_step_at = datetime.utcnow() - timedelta(days=15)
    db.commit()
    db.expire_all()
    assert autopilot.check(db, db.query(models.DmarcAutopilot).one())["to"] == "reject"
    assert _dmarc(store) == ["v=DMARC1; p=reject; rua=mailto:d@acme.com"]
    ap = db.query(models.DmarcAutopilot).one()
    assert ap.status == "done" and [x["to"] for x in ap.history] == ["quarantine", "reject"]


def test_steps_back_and_pauses_when_real_mail_fails(setup, db):
    owner, store, sent, c, h = setup
    _reports(db, owner.tenant_id, 15, 15, [GOOD])
    c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True})
    assert "p=quarantine" in _dmarc(store)[0]
    # A real service starts failing after the step.
    _reports(db, owner.tenant_id, 0, 1, [GOOD, UNSIGNED_SENDGRID])
    ap = db.query(models.DmarcAutopilot).one()
    ap.last_step_at = datetime.utcnow() - timedelta(days=2)
    db.commit()
    r = c.post("/api/autopilot/acme.com/check", headers=h).json()
    assert r["decision"]["action"] == "rollback" and r["status"] == "paused" and "SendGrid" in r["message"]
    assert "p=none" in _dmarc(store)[0]
    assert sent[-1] == "DMARC for acme.com stepped back to p=none"
    # Paused: the scheduler skips it, check is refused until resumed.
    assert c.post("/api/autopilot/acme.com/check", headers=h).status_code == 409
    assert autopilot.run_all(db)["checked"] == 0
    assert c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True}).json()["status"] != "paused"


def test_manual_step_back(setup, db):
    owner, store, sent, c, h = setup
    store[0] = ("_dmarc.acme.com", "TXT", "v=DMARC1; p=reject; t=y; rua=mailto:d@acme.com")
    c.put("/api/autopilot/acme.com", headers=h, json={"enabled": False})
    r = c.post("/api/autopilot/acme.com/step-back", headers=h).json()
    assert r["status"] == "paused" and r["history"][0]["to"] == "quarantine"
    assert _dmarc(store) == ["v=DMARC1; p=quarantine; rua=mailto:d@acme.com"]


def test_hosted_dmarc_mode(setup, db, monkeypatch):
    owner, store, sent, c, h = setup
    owner.tenant.dns_token = None
    db.add(models.HostedRecord(tenant_id=owner.tenant_id, domain="acme.com", kind="dmarc",
                               config={"p": "none", "t": True, "rua": ["d@acme.com"], "adkim": "r", "aspf": "r"}))
    db.commit()
    monkeypatch.setattr("app.hosted.configured", lambda: True)
    published = []
    monkeypatch.setattr("app.hosted.publish", lambda rec, **kw: published.append(dict(rec.config)))
    _reports(db, owner.tenant_id, 15, 15, [GOOD])
    r = c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True, "target": "quarantine"}).json()
    assert r["mode"] == "hosted" and r["status"] == "done"
    assert published[-1]["p"] == "quarantine" and published[-1]["t"] is False


def test_needs_a_way_to_change_the_record_and_admin_role(setup, db):
    owner, store, sent, c, h = setup
    owner.tenant.dns_token = None
    db.commit()
    assert c.put("/api/autopilot/acme.com", headers=h, json={"enabled": True}).status_code == 400
    member = make_user(db, "m@acme.com", role="member", tenant=owner.tenant, mfa=False)
    mh = {"Authorization": f"Bearer {login_as(c, member, keep_cookies=False)['access_token']}"}
    assert c.put("/api/autopilot/acme.com", headers=mh, json={"enabled": False}).status_code == 403
    assert c.put("/api/autopilot/other.com", headers=h, json={"enabled": False}).status_code == 400


def test_policy_rewrite():
    assert autopilot._with_policy("v=DMARC1; p=none; t=y; rua=mailto:a@b.c", "reject") == \
        "v=DMARC1; p=reject; rua=mailto:a@b.c"
    assert autopilot._with_policy("v=DMARC1; rua=mailto:a@b.c", "quarantine") == \
        "v=DMARC1; p=quarantine; rua=mailto:a@b.c"
    assert autopilot._policy("v=DMARC1; sp=reject; p=quarantine") == "quarantine"
