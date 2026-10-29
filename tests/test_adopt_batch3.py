"""More DMARC report views, scheduled PDF reports, and the MSP overview."""
from datetime import datetime, timedelta

from app import ip_enrich, mailer, models, scheduled_reports
from app.dmarc_reports import summarize
from tests.test_fill_gaps import _auth, client, db  # noqa: F401  (fixtures)
from tests.conftest import admin_tenant


# ------------------------------------------------------------------ report views
def test_summary_counts_per_ip_and_groups_by_host_and_country(monkeypatch):
    from types import SimpleNamespace
    when = datetime.utcnow()
    rec = lambda ip, n, ok: {"source_ip": ip, "count": n, "dkim": "pass" if ok else "fail", "spf": "fail",
                             "dkim_auth": [], "spf_auth": [], "envelope_from": ""}
    rep = SimpleNamespace(org_name="g", policy={"p": "none"}, date_begin=when, date_end=when, created_at=when,
                          records=[rec("192.0.2.1", 80, True), rec("192.0.2.1", 20, False),
                                   rec("192.0.2.2", 50, True), rec("198.51.100.9", 5, False)])
    s = summarize([rep], "x.com", 30)
    assert s["ips"] == [{"ip": "192.0.2.1", "messages": 100, "passed": 80},
                        {"ip": "192.0.2.2", "messages": 50, "passed": 50},
                        {"ip": "198.51.100.9", "messages": 5, "passed": 0}]
    info = {"192.0.2.1": {"ptr": "o1.mail.sendgrid.net", "country": "US"},
            "192.0.2.2": {"ptr": "o2.sendgrid.net", "country": "IE"},
            "198.51.100.9": {"ptr": None, "country": None}}
    monkeypatch.setattr(ip_enrich, "lookup", lambda ip: {"ip": ip, **info[ip]})
    out = ip_enrich.enrich_summary(s)
    assert out["by_host"] == [
        {"host": "sendgrid.net", "messages": 150, "passed": 130, "ips": 2, "pass_rate": 86.7},
        {"host": None, "messages": 5, "passed": 0, "ips": 1, "pass_rate": 0.0}]
    assert [(c["country"], c["messages"]) for c in out["by_country"]] == [("US", 100), ("IE", 50), (None, 5)]
    assert out["geoip"] is False


# ------------------------------------------------------------------ scheduled reports
def _tenant(db, *_args):
    return admin_tenant(db)


def test_schedule_api_and_send_now(client, db, monkeypatch):
    h = _auth(client, "o@x.com")
    assert client.get("/api/team/report-schedule", headers=h).json() == {
        "schedule": "off", "last_sent": None, "email_configured": False}
    assert client.put("/api/team/report-schedule", json={"schedule": "daily"}, headers=h).status_code == 422
    assert client.put("/api/team/report-schedule", json={"schedule": "weekly"}, headers=h).json()["schedule"] == "weekly"
    assert client.post("/api/team/report-schedule/send-now", headers=h).status_code == 503
    sent = []
    monkeypatch.setattr(mailer, "is_configured", lambda: True)
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, body, attachments=None: sent.append((to, subject, body, attachments)) or True)
    assert client.post("/api/team/report-schedule/send-now", headers=h).status_code == 400  # nothing monitored
    client.post("/api/monitors", json={"domain": "x.com", "client": "Acme"}, headers=h)
    r = client.post("/api/team/report-schedule/send-now", headers=h)
    assert r.status_code == 200 and r.json()["last_sent"]
    to, subject, body, att = sent[0]
    assert to == ["owner@x.com"] and subject.startswith("Weekly email security report")
    assert "x.com [Acme]" in body and att[0][2] == "application/pdf" and att[0][1].startswith(b"%PDF")


def test_send_due_respects_schedule(client, db, monkeypatch):
    h = _auth(client, "o@x.com")
    client.post("/api/monitors", json={"domain": "x.com"}, headers=h)
    t = _tenant(db, "o@x.com")
    t.alert_emails = ["tickets@psa.test"]
    db.commit()
    sent = []
    monkeypatch.setattr(mailer, "send_email", lambda to, *a, **k: sent.append(to) or True)
    assert scheduled_reports.send_due(db) == 0  # SMTP not configured
    monkeypatch.setattr(mailer, "is_configured", lambda: True)
    assert scheduled_reports.send_due(db) == 0  # schedule off
    t.report_schedule = "monthly"
    db.commit()
    now = datetime.utcnow()
    assert scheduled_reports.send_due(db, now) == 1
    assert sent == [["owner@x.com", "tickets@psa.test"]]
    assert scheduled_reports.send_due(db, now + timedelta(days=20)) == 0
    assert scheduled_reports.send_due(db, now + timedelta(days=30)) == 1


# ------------------------------------------------------------------ overview
def test_overview(client, db):
    h = _auth(client, "o@x.com")
    for d, c in (("a.com", "Acme"), ("b.com", "Acme"), ("c.com", None)):
        client.post("/api/monitors", json={"domain": d, "client": c}, headers=h)
    mons = {m.domain: m for m in db.query(models.Monitor).all()}
    mons["a.com"].last_score, mons["b.com"].last_score, mons["c.com"].last_score = 90, 50, 70
    t = _tenant(db, "o@x.com")
    db.add_all([models.Alert(tenant_id=t.id, monitor_id=mons["b.com"].id, kind="score_drop", message="m"),
                models.Alert(tenant_id=t.id, monitor_id=mons["b.com"].id, kind="dns_changed", message="m"),
                models.Alert(tenant_id=t.id, monitor_id=mons["c.com"].id, kind="score_drop", message="m")])
    db.commit()
    client.post("/api/monitors", json={"domain": "d.com"}, headers=h)
    d_id = next(m["id"] for m in client.get("/api/monitors", headers=h).json() if m["domain"] == "d.com")
    client.delete(f"/api/monitors/{d_id}", headers=h)
    o = client.get("/api/overview", headers=h).json()
    assert o["totals"] == {"domains": 3, "active": 3, "paused": 0, "clients": 1, "avg_score": 70,
                           "added_this_month": 3, "removed_this_month": 1, "alerts_30d": 3, "dns_changes_30d": 0}
    assert [(m["domain"], m["grade"]) for m in o["lowest"]] == [("b.com", "F"), ("c.com", "C"), ("a.com", "A")]
    assert o["alert_kinds"][0] == {"kind": "score_drop", "count": 2}
    assert o["noisiest"][0]["domain"] == "b.com" and o["noisiest"][0]["alerts_30d"] == 2
    acme = next(c for c in o["clients"] if c["client"] == "Acme")
    assert acme == {"client": "Acme", "domains": 2, "avg_score": 70, "below_70": 1, "alerts_30d": 2,
                    "lowest": {**acme["lowest"], "domain": "b.com", "score": 50}}
    assert client.get("/overview", follow_redirects=False).status_code == 302
