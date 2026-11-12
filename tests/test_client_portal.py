"""MSP client portal: a client login sees its own client's domains, read-only,
and nothing else of the MSP's company."""
import pytest
from fastapi.testclient import TestClient

from app import models
from app.config import settings
from app.main import app
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)

RESULT = {"domain": "x", "checks": [{"key": "dmarc", "name": "DMARC", "status": "fail", "score": 0, "max_score": 20,
                                     "issues": ["No DMARC record"], "fixes": ["Publish v=DMARC1; p=none"]}],
          "action_plan": [], "recommendations": []}


@pytest.fixture()
def msp(db):  # noqa: F811
    owner = make_user(db, "boss@msp.com", company="Best MSP")
    t = owner.tenant_id
    db.add_all([models.Monitor(tenant_id=t, domain="acme.com", client="Acme", last_score=55),
                models.Monitor(tenant_id=t, domain="acme.net", client="Acme"),
                models.Monitor(tenant_id=t, domain="globex.com", client="Globex", last_score=90)])
    scans = {d: models.Scan(tenant_id=t, domain=d, score=50, grade="D", result={**RESULT, "domain": d})
             for d in ("acme.com", "globex.com")}
    db.add_all(scans.values())
    db.commit()
    db.add(models.Alert(tenant_id=t, monitor_id=db.query(models.Monitor).filter_by(domain="acme.com").one().id,
                        kind="score_drop", message="Score dropped"))
    db.commit()
    c = TestClient(app)
    oh = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    return owner, c, oh, {d: s.id for d, s in scans.items()}


def _client_login(c, oh, client="Acme"):
    """A client account, past its first sign-in (password changed)."""
    r = c.post("/api/users", headers=oh, json={"email": "it@acme.com", "role": "client", "client": client,
                                               "send_email": False})
    assert r.status_code in (200, 201), r.text
    assert r.json()["client"] == client and r.json()["role"] == "client"
    from app.database import SessionLocal
    s = SessionLocal()
    u = s.get(models.User, r.json()["id"])
    u.status, u.must_change_password = "active", False
    s.commit()
    s.close()
    return r.json()["id"]


def test_client_sees_only_their_domains(msp, db):  # noqa: F811
    owner, c, oh, scans = msp
    uid = _client_login(c, oh)
    ch = {"Authorization": f"Bearer {login_as(c, uid, keep_cookies=False)['access_token']}"}
    p = c.get("/api/portal", headers=ch).json()
    assert p["client"] == "Acme" and p["provider"] == "Best MSP"
    assert [d["domain"] for d in p["domains"]] == ["acme.com", "acme.net"]
    assert p["domains"][0]["scan_id"] == scans["acme.com"] and p["domains"][1]["scan_id"] is None
    assert [a["domain"] for a in p["alerts"]] == ["acme.com"]
    assert c.get(f"/api/portal/scans/{scans['acme.com']}", headers=ch).json()["domain"] == "acme.com"
    # Another client's report, in the same MSP company: not found.
    assert c.get(f"/api/portal/scans/{scans['globex.com']}", headers=ch).status_code == 404
    assert c.get(f"/api/portal/scans/{scans['globex.com']}/pdf", headers=ch).status_code == 404


@pytest.mark.parametrize("path", ["/api/monitors", "/api/scans", "/api/users", "/api/overview", "/api/tasks", "/api/team/keys",
                                  "/api/scans/whatever", "/api/phish-reports", "/api/team/audit"])
def test_every_other_api_is_refused(msp, path):
    owner, c, oh, scans = msp
    ch = {"Authorization": f"Bearer {login_as(c, _client_login(c, oh), keep_cookies=False)['access_token']}"}
    assert c.get(path, headers=ch).status_code == 403
    assert c.get("/api/auth/me", headers=ch).status_code == 200


def test_pages_send_clients_to_the_portal(msp):
    owner, c, oh, scans = msp
    login_as(c, _client_login(c, oh))
    for page in ("/dashboard", "/overview", "/setup"):
        r = c.get(page, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/portal"
    assert c.get("/portal").status_code == 200
    login_as(c, owner)
    assert c.get("/portal", follow_redirects=False).headers["location"] == "/dashboard"
    assert c.get("/api/portal").status_code == 403


def test_client_label_must_exist_and_changes_end_sessions(msp, db):  # noqa: F811
    owner, c, oh, scans = msp
    r = c.post("/api/users", headers=oh, json={"email": "x@y.com", "role": "client", "client": "Nobody",
                                               "send_email": False})
    assert r.status_code == 400
    r = c.post("/api/users", headers=oh, json={"email": "x@y.com", "role": "client", "send_email": False})
    assert r.status_code == 400
    uid = _client_login(c, oh)
    ch = {"Authorization": f"Bearer {login_as(c, uid, keep_cookies=False)['access_token']}"}
    r = c.patch(f"/api/users/{uid}", headers=oh, json={"client": "Globex"})
    assert r.status_code == 200 and r.json()["client"] == "Globex"
    assert c.get("/api/portal", headers=ch).status_code == 401  # old session revoked
    # Promoted to member: the client label goes away.
    r = c.patch(f"/api/users/{uid}", headers=oh, json={"role": "member"})
    assert r.json()["client"] is None and db.get(models.User, uid).client_scope is None


def test_api_keys_refused_for_clients(msp, db):  # noqa: F811
    owner, c, oh, scans = msp
    uid = _client_login(c, oh)
    import hashlib
    raw = "plk_clienttest"
    db.add(models.ApiKey(tenant_id=owner.tenant_id, user_id=uid, name="x", prefix="plk_clie",
                         key_hash=hashlib.sha256(raw.encode()).hexdigest()))
    db.commit()
    assert c.get("/api/portal", headers={"X-API-Key": raw}).status_code == 403


def test_needs_msp_plan_when_plans_are_on(msp, monkeypatch, db):  # noqa: F811
    owner, c, oh, scans = msp
    monkeypatch.setattr(settings, "PLANS_ENABLED", True)
    db.get(models.Tenant, owner.tenant_id).plan = "pro"
    db.commit()
    r = c.post("/api/users", headers=oh, json={"email": "it@acme.com", "role": "client", "client": "Acme",
                                               "send_email": False})
    assert r.status_code == 403 and "MSP" in r.json()["detail"]
