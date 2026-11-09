"""DMARC sender classification: confidence, categories, approve/block, auto-approve."""
from datetime import datetime, timedelta

from app import dmarc_reports, models
from tests.conftest import make_user, login_as
from tests.test_market_gaps import _report, client, db  # noqa: F401  (fixtures)


def _upload(client, h, **kw):
    r = client.post("/api/dmarc/reports", headers=h, content=_report(**kw))
    assert r.status_code == 201, r.text


def _seed(client, h):
    rows = [("209.85.220.41", 900, "pass", "pass", "google.com"),
            ("198.51.100.7", 100, "fail", "fail", "spoofer.example"),
            ("203.0.113.9", 50, "fail", "fail", "sendgrid.net")]
    for i in (1, 2, 3, 20):  # spans more than two weeks
        _upload(client, h, report_id=f"r-{i}", begin=datetime.utcnow() - timedelta(days=i), rows=rows)


def _by_sender(s):
    return {r["sender"]: r for r in s["senders"]}


def _owner_headers(client, db):
    owner = make_user(db, "owner@x.com")
    return {"Authorization": f"Bearer {login_as(client, owner, keep_cookies=False)['access_token']}"}, owner


def test_senders_are_classified_with_confidence(client, db):
    h, _ = _owner_headers(client, db)
    _seed(client, h)
    s = client.get("/api/dmarc/summary/example.com?enrich=false", headers=h).json()
    rows = _by_sender(s)
    assert rows["Google Workspace"]["category"] == "authorized" and rows["Google Workspace"]["confidence"] >= 90
    assert rows["SendGrid"]["category"] == "needs_fix"  # a real service, not signing for you yet
    assert rows["spoofer.example"]["category"] == "suspicious" and rows["spoofer.example"]["confidence"] < 50
    assert "Probably spoofing" in rows["spoofer.example"]["fix"]
    assert s["categories"]["suspicious"] == 1 and s["auto_approve"] is False
    # Only the misconfigured real service holds up enforcement, not the spoofer.
    assert "SendGrid" in s["verdict"]["message"] and "spoofer" not in s["verdict"]["message"]


def test_approve_and_block_senders(client, db):
    h, _ = _owner_headers(client, db)
    _seed(client, h)
    for sender, verdict in (("spoofer.example", "blocked"), ("SendGrid", "approved")):
        assert client.put("/api/dmarc/senders/example.com", headers=h,
                          json={"sender": sender, "verdict": verdict}).status_code == 200
    rows = _by_sender(client.get("/api/dmarc/summary/example.com?enrich=false", headers=h).json())
    assert rows["spoofer.example"]["category"] == "blocked" and "not yours" in rows["spoofer.example"]["fix"]
    assert rows["SendGrid"]["category"] == "approved" and rows["SendGrid"]["rule_source"] == "manual"
    client.put("/api/dmarc/senders/example.com", headers=h, json={"sender": "spoofer.example", "verdict": None})
    rows = _by_sender(client.get("/api/dmarc/summary/example.com?enrich=false", headers=h).json())
    assert rows["spoofer.example"]["category"] == "suspicious"
    assert client.put("/api/dmarc/senders/example.com", headers=h,
                      json={"sender": "x", "verdict": "maybe"}).status_code == 422


def test_members_cannot_change_senders(client, db):
    _, owner = _owner_headers(client, db)
    member = make_user(db, "m@x.com", role="member", tenant=owner.tenant, mfa=False)
    mh = {"Authorization": f"Bearer {login_as(client, member, keep_cookies=False)['access_token']}"}
    assert client.put("/api/dmarc/senders/example.com", headers=mh,
                      json={"sender": "Google", "verdict": "approved"}).status_code == 403
    assert client.put("/api/dmarc/auto-approve", headers=mh, json={"enabled": True}).status_code == 403


def test_auto_approve_only_takes_clear_senders(client, db):
    h, owner = _owner_headers(client, db)
    _seed(client, h)
    assert client.put("/api/dmarc/auto-approve", headers=h, json={"enabled": True}).json() == {"enabled": True}
    s = client.get("/api/dmarc/summary/example.com?enrich=false", headers=h).json()
    rows = _by_sender(s)
    assert rows["Google Workspace"]["category"] == "approved" and rows["Google Workspace"]["rule_source"] == "auto"
    assert rows["SendGrid"]["category"] == "needs_fix" and rows["spoofer.example"]["category"] == "suspicious"
    saved = db.query(models.SenderRule).filter_by(tenant_id=owner.tenant_id).all()
    assert [(r.sender, r.verdict, r.source) for r in saved] == [("Google Workspace", "approved", "auto")]
    # Repeat views don't duplicate the rule.
    client.get("/api/dmarc/summary/example.com?enrich=false", headers=h)
    assert db.query(models.SenderRule).filter_by(tenant_id=owner.tenant_id).count() == 1


def test_rules_are_per_company(client, db):
    h, _ = _owner_headers(client, db)
    _seed(client, h)
    client.put("/api/dmarc/senders/example.com", headers=h, json={"sender": "spoofer.example", "verdict": "approved"})
    other = make_user(db, "o@other.com", company="Other")
    oh = {"Authorization": f"Bearer {login_as(client, other, keep_cookies=False)['access_token']}"}
    _seed(client, oh)
    rows = _by_sender(client.get("/api/dmarc/summary/example.com?enrich=false", headers=oh).json())
    assert rows["spoofer.example"]["category"] == "suspicious"


def test_classify_unknown_sender_low_confidence():
    row = {"sender": "Unknown sender", "messages": 3, "pass_rate": 0.0, "status": "fail",
           "days_seen": 1, "reporter_count": 1}
    out = dmarc_reports.classify(row)
    assert out["category"] == "suspicious" and out["confidence"] == 0 and not out["auto_approvable"]
