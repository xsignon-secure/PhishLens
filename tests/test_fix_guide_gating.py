"""Free report vs fix guide: the fixes (records and step-by-step guides) are
for signed-in accounts only, on every way a scan leaves the server; and the
public sign-up that gives people an account."""
import pytest
from fastapi.testclient import TestClient

from app import mailer, models
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from app.routers import signup as signup_router
from app.scanner import gating
from tests.conftest import login_as, make_user

FIX = "v=DMARC1; p=none; rua=mailto:dmarc@acme.example"


def _checks(domain):
    return [
        {"key": "dmarc", "title": "DMARC", "status": "fail", "score": 0, "max_score": 20,
         "details": "No DMARC record found.", "issues": ["No DMARC record"], "fixes": [FIX]},
        {"key": "spf", "title": "SPF", "status": "pass", "score": 15, "max_score": 15,
         "details": "SPF ok.", "issues": [], "fixes": []},
    ]


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", _checks)
    monkeypatch.setattr("app.scanner.reputation.lookup", lambda d: None)
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    return TestClient(app)


def _no_solutions(payload):
    """Nothing in the payload tells the reader how to fix it."""
    text = str(payload)
    assert FIX not in text and "'guide'" not in text and "'records'" not in text


def _pdf_text(data: bytes) -> str:
    """The PDF's text drawing operators (pages are written uncompressed in
    these tests, see the client fixture)."""
    return data.decode("latin-1")


# ------------------------------------------------------------------ gating unit
def test_findings_only_keeps_findings_and_priorities_but_no_fixes():
    result = {"checks": _checks("acme.example"),
              "action_plan": [{"check": "DMARC", "fix": FIX, "points": 20, "guide": {"steps": ["x"]}}]}
    result["checks"][0]["guide"] = {"steps": ["Sign in to your DNS host"], "records": [{"value": FIX}]}
    out = gating.findings_only(result)
    _no_solutions(out)
    assert out["solutions_locked"] and out["locked_fixes"] == 1
    assert out["action_plan"] == [{"check": "DMARC", "points": 20}]
    assert out["checks"][0]["details"] == "No DMARC record found."
    assert out["checks"][0]["issues"] == ["No DMARC record"]
    assert out["checks"][0]["solutions_locked"] and not out["checks"][1]["solutions_locked"]
    assert result["checks"][0]["fixes"] == [FIX]  # the stored scan is untouched


# ------------------------------------------------------------------ anonymous visitors
def test_anonymous_landing_scan_has_no_fixes_in_json_or_pdf(client):
    r = client.post("/api/scans/public", json={"domain": "acme.com"})
    assert r.status_code == 200, r.text
    body = r.json()
    _no_solutions(body)
    assert body["result"]["solutions_locked"] and body["result"]["locked_fixes"] == 1
    assert client.get(f"/api/scans/public/{body['id']}").json()["result"]["solutions_locked"]

    pdf = client.get(f"/api/scans/public/{body['id']}/pdf")
    assert pdf.status_code == 200
    text = _pdf_text(pdf.content)
    assert "No DMARC record found" in text and "rua=mailto:dmarc@acme.example" not in text
    assert "fix guide" in text.lower()

    assert client.get(f"/api/scans/public/{body['id']}/guide.pdf").status_code == 401


def test_shared_report_link_hides_fixes_from_anonymous_viewers(client, db):
    owner = make_user(db)
    login_as(client, owner)
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    scan_id = client.post("/api/scans", json={"domain": "acme.com"}, headers=h).json()["id"]
    assert client.post(f"/api/scans/{scan_id}/share", headers=h).status_code == 200
    anon = TestClient(app)
    _no_solutions(anon.get(f"/api/scans/shared/{scan_id}").json())
    page = anon.get(f"/r/{scan_id}")
    assert page.status_code == 200 and FIX not in page.text
    assert "rua=mailto:dmarc@acme.example" not in _pdf_text(anon.get(f"/api/scans/shared/{scan_id}/pdf").content)
    assert anon.get(f"/api/scans/shared/{scan_id}/guide.pdf").status_code == 401
    # Signed in, the same link shows the fixes.
    assert FIX in str(client.get(f"/api/scans/shared/{scan_id}").json())
    assert FIX in client.get(f"/r/{scan_id}").text


def test_single_record_checker_hides_fixes_unless_signed_in(client, db, monkeypatch):
    from app.routers import tools
    monkeypatch.setitem(tools.SINGLE_CHECKS, "dmarc", lambda d: _checks(d)[0])
    monkeypatch.setattr("app.routers.tools.assert_public_target", lambda d: None)
    r = client.post("/api/tools/check", json={"domain": "acme.com", "check": "dmarc"}).json()
    assert r["fixes"] == [] and r["solutions_locked"]
    login_as(client, make_user(db))
    assert client.post("/api/tools/check", json={"domain": "acme.com", "check": "dmarc"}).json()["fixes"] == [FIX]


# ------------------------------------------------------------------ signed-in accounts
def test_signed_in_users_get_fixes_and_a_separate_fix_guide_pdf(client, db):
    login_as(client, make_user(db))
    body = client.post("/api/scans/public", json={"domain": "acme.com"}).json()
    assert FIX in str(body) and not body["result"].get("solutions_locked")
    guide = client.get(f"/api/scans/public/{body['id']}/guide.pdf")
    assert guide.status_code == 200 and "fix-guide" in guide.headers["content-disposition"]
    assert "Fix guide" in _pdf_text(guide.content)

    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    scan = client.post("/api/scans", json={"domain": "acme.com"}, headers=h).json()
    assert scan["result"]["checks"][0]["guide"]
    report = _pdf_text(client.get(f"/api/scans/{scan['id']}/pdf").content)
    guide = _pdf_text(client.get(f"/api/scans/{scan['id']}/guide.pdf").content)
    assert "No DMARC record found" in report and "_dmarc" not in report
    assert "_dmarc" in guide


def test_other_companies_cannot_fetch_a_teams_guide(client, db):
    a = make_user(db, "a@a.com", company="A")
    b = make_user(db, "b@b.com", company="B")
    login_as(client, a)
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    scan_id = client.post("/api/scans", json={"domain": "acme.com"}, headers=h).json()["id"]
    other = TestClient(app)
    login_as(other, b)
    assert other.get(f"/api/scans/{scan_id}/guide.pdf").status_code == 404


# ------------------------------------------------------------------ sign-up
@pytest.fixture()
def signup_on(monkeypatch):
    sent = []
    monkeypatch.setattr(settings, "SIGNUP_ENABLED", True)
    monkeypatch.setattr(mailer, "is_configured", lambda: True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.server.example")
    monkeypatch.setattr(settings, "SMTP_FROM", "noreply@server.example")
    monkeypatch.setattr(mailer, "deliver", lambda cfg, msg: sent.append((cfg, msg)))
    monkeypatch.setattr(signup_router, "mail_domain_ok", lambda d: d != "nowhere.example")
    return sent


def _form(**kw):
    return {"company": "Acme", "full_name": "Ana", "email": "ana@acme.example", "accept_terms": True, **kw}


def test_signup_creates_a_free_company_and_emails_login_details(client, db, signup_on):
    assert client.get("/signup").status_code == 200
    r = client.post("/api/auth/signup", json=_form())
    assert r.status_code == 202, r.text
    user = db.query(models.User).filter_by(email="ana@acme.example").one()
    assert user.role == "owner" and user.status == "pending"
    assert user.tenant.plan == "free" and user.tenant.name == "Acme"
    assert len(signup_on) == 1 and signup_on[0][1]["To"] == "ana@acme.example"
    assert "Temporary password:" in signup_on[0][1].get_content()


def test_signup_does_not_reveal_existing_accounts(client, db, signup_on):
    make_user(db, "ana@acme.example")
    r = client.post("/api/auth/signup", json=_form(company="Other"))
    assert r.status_code == 202 and r.json() == signup_router.DONE
    assert db.query(models.Tenant).count() == 1 and not signup_on


def test_signup_rejects_bad_input_and_bots(client, db, signup_on):
    assert client.post("/api/auth/signup", json=_form(accept_terms=False)).status_code == 400
    assert client.post("/api/auth/signup", json=_form(email="x@mailinator.com")).status_code == 400
    assert client.post("/api/auth/signup", json=_form(email="x@nowhere.example")).status_code == 400
    assert client.post("/api/auth/signup", json=_form(website="http://spam")).status_code == 202
    assert db.query(models.Tenant).count() == 0 and not signup_on


def test_signup_is_rate_limited_per_ip(client, db, signup_on, monkeypatch):
    monkeypatch.setattr(settings, "SIGNUPS_PER_IP_PER_HOUR", 2)
    codes = [client.post("/api/auth/signup", json=_form(email=f"u{i}@acme.example")).status_code
             for i in range(3)]
    assert codes == [202, 202, 429]


def test_signup_off_by_default_and_needs_a_mail_server(client, db, monkeypatch):
    assert client.post("/api/auth/signup", json=_form()).status_code == 404
    monkeypatch.setattr(settings, "SIGNUP_ENABLED", True)
    monkeypatch.setattr(mailer, "is_configured", lambda: False)
    assert client.post("/api/auth/signup", json=_form()).status_code == 503
    assert client.get("/signup", follow_redirects=False).status_code == 302
