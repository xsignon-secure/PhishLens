"""Remediation tasks: assign findings with due dates, close on a passing scan."""
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app import models, tasks
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import login_as, make_user


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


def _scan(db, tenant_id, domain, dmarc="fail"):
    s = models.Scan(tenant_id=tenant_id, domain=domain, score=50, grade="C",
                    result={"checks": [{"key": "dmarc", "title": "DMARC", "status": dmarc},
                                       {"key": "spf", "title": "SPF", "status": "pass"}]})
    db.add(s)
    db.commit()
    return s


@pytest.fixture()
def setup(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    owner = make_user(db, "boss@acme.com", company="Acme")
    member = make_user(db, "it@acme.com", role="member", tenant=owner.tenant, mfa=False)
    other = make_user(db, "boss@other.com", company="Other")
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="acme.com", client="Acme Retail"))
    db.add(models.Monitor(tenant_id=other.tenant_id, domain="acme.com"))
    db.commit()
    _scan(db, owner.tenant_id, "acme.com")
    c = TestClient(app)

    def h(u):
        return {"Authorization": f"Bearer {login_as(c, u, keep_cookies=False)['access_token']}"}
    return owner, member, other, c, h(owner), h(member), h(other)


def test_assign_finding_and_isolation(setup):
    owner, member, other, c, oh, mh, xh = setup
    due = (date.today() + timedelta(days=7)).isoformat()
    r = c.post("/api/tasks", json={"domain": "acme.com", "check_key": "dmarc", "assignee_id": member.id,
                                   "due_date": due}, headers=oh)
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["title"] == "Fix DMARC" and t["assignee"] == "it@acme.com" and t["client"] == "Acme Retail"
    assert c.post("/api/tasks", json={"domain": "acme.com", "check_key": "dmarc"}, headers=oh).status_code == 409
    assert c.post("/api/tasks", json={"domain": "acme.com", "check_key": "bimi"}, headers=oh).status_code == 400
    assert c.post("/api/tasks", json={"domain": "nope.com", "title": "x"}, headers=oh).status_code == 400
    # Members can't create, and can't assign to another company's user.
    assert c.post("/api/tasks", json={"domain": "acme.com", "title": "x"}, headers=mh).status_code == 403
    assert c.post("/api/tasks", json={"domain": "acme.com", "title": "x", "assignee_id": other.id},
                  headers=oh).status_code == 400
    # The other company sees nothing and can't touch it.
    assert c.get("/api/tasks", headers=xh).json() == []
    assert c.patch(f"/api/tasks/{t['id']}", json={"status": "done"}, headers=xh).status_code == 404
    assert [x["id"] for x in c.get("/api/tasks?mine=true", headers=mh).json()] == [t["id"]]


def test_member_can_only_close_own_task(setup, db):
    owner, member, other, c, oh, mh, xh = setup
    mine = c.post("/api/tasks", json={"domain": "acme.com", "title": "Rotate DKIM", "assignee_id": member.id},
                  headers=oh).json()
    theirs = c.post("/api/tasks", json={"domain": "acme.com", "title": "Add BIMI"}, headers=oh).json()
    assert c.patch(f"/api/tasks/{mine['id']}", json={"due_date": "2030-01-01"}, headers=mh).status_code == 403
    assert c.patch(f"/api/tasks/{theirs['id']}", json={"status": "done"}, headers=mh).status_code == 403
    r = c.patch(f"/api/tasks/{mine['id']}", json={"status": "done"}, headers=mh).json()
    assert r["status"] == "done" and r["closed_by"] == "it@acme.com"
    assert c.delete(f"/api/tasks/{theirs['id']}", headers=mh).status_code == 403
    assert c.delete(f"/api/tasks/{theirs['id']}", headers=oh).status_code == 204
    assert db.query(models.AuditEvent).filter(models.AuditEvent.action.like("task.%")).count() == 4


def test_passing_scan_closes_task(setup, db):
    owner, member, other, c, oh, mh, xh = setup
    t = c.post("/api/tasks", json={"domain": "acme.com", "check_key": "dmarc"}, headers=oh).json()
    # The other company's scan of the same domain must not close Acme's task.
    tasks.verify(db, _scan(db, other.tenant_id, "acme.com", dmarc="pass"))
    assert c.get("/api/tasks", headers=oh).json()[0]["status"] == "open"
    tasks.verify(db, _scan(db, owner.tenant_id, "acme.com", dmarc="pass"))
    assert c.get("/api/tasks", headers=oh).json() == []
    done = c.get("/api/tasks?status=done", headers=oh).json()
    assert done[0]["id"] == t["id"] and done[0]["closed_by"] == "scan"


def test_run_scan_hook_verifies(setup, db, monkeypatch):
    owner, member, other, c, oh, mh, xh = setup
    c.post("/api/tasks", json={"domain": "acme.com", "check_key": "spf"}, headers=oh)  # spf already passing
    monkeypatch.setattr("app.scanner.scoring.run_all_checks",
                        lambda d: [{"key": "spf", "title": "SPF", "status": "pass", "score": 10, "max_score": 10, "fixes": []}])
    from app.scanner import engine
    engine.run_scan(db, "acme.com", tenant_id=owner.tenant_id)
    assert c.get("/api/tasks", headers=oh).json() == []


def test_overdue_summary_and_reminder(setup, db, monkeypatch):
    owner, member, other, c, oh, mh, xh = setup
    late = (date.today() - timedelta(days=2)).isoformat()
    c.post("/api/tasks", json={"domain": "acme.com", "title": "Late one", "assignee_id": member.id,
                               "due_date": late}, headers=oh)
    c.post("/api/tasks", json={"domain": "acme.com", "title": "No date"}, headers=oh)
    rows = c.get("/api/tasks", headers=oh).json()
    assert rows[0]["title"] == "Late one" and rows[0]["overdue"] is True
    s = c.get("/api/tasks/summary", headers=mh).json()
    assert s["open"] == 2 and s["overdue"] == 1 and s["mine"] == 1
    assert s["by_client"] == [{"client": "Acme Retail", "open": 2, "overdue": 1}]
    sent = []
    monkeypatch.setattr("app.mailer.send_email", lambda to, subject, body, **kw: sent.append((to, subject, body)) or True)
    assert tasks.remind_overdue(db) == 1
    assert sent[0][0] == ["it@acme.com"] and "Late one" in sent[0][2]
    assert tasks.remind_overdue(db) == 0  # once only
