"""Report-phish button: Outlook add-in / Gmail add-on send reports with a
company token that can only submit."""
import xml.etree.ElementTree as ET

import pytest

from app import models, report_button
from app.config import settings
from tests.conftest import login_as, make_user
from tests.test_phish_reports import _phish, db, fake_check, setup  # noqa: F401  (fixtures)


@pytest.fixture()
def rb(setup, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "AI_PROVIDER", "")
    monkeypatch.setattr(settings, "APP_URL", "https://phishlens.example")
    monkeypatch.setattr("app.phish_reports.takedown", lambda *a, **k: {"domain": a[0], "to": []})
    owner, c, oh, mh = setup
    files = c.post("/api/report-button/token", headers=oh).json()
    return owner, c, oh, mh, files


def test_only_admins_make_a_token(rb):
    owner, c, oh, mh, files = rb
    assert c.post("/api/report-button/token", headers=mh).status_code == 403
    assert files["token"].startswith("plr_")
    assert c.get("/api/report-button", headers=mh).json()["enabled"] is True


def test_report_with_token(rb, db):  # noqa: F811
    owner, c, oh, mh, files = rb
    r = c.post("/api/report-button/report", content=_phish(),
               headers={"X-Report-Token": files["token"], "X-Reporter": "jane@acme.com",
                        "Content-Type": "message/rfc822"})
    assert r.status_code == 201 and r.json()["verdict"] == "dangerous"
    assert set(r.json()) == {"id", "verdict"}  # the token can't read anything back
    rows = c.get("/api/phish-reports", headers=mh).json()
    assert rows[0]["reported_by"] == "jane@acme.com" and rows[0]["verdict"] == "dangerous"
    # Takedown drafts open just like for uploads.
    assert c.get("/api/phish-reports/takedowns", headers=mh).json()[0]["auto"]


def test_bad_token_and_no_reading(rb):
    owner, c, oh, mh, files = rb
    assert c.post("/api/report-button/report", content=_phish(), headers={"X-Report-Token": "plr_nope"}).status_code == 401
    assert c.post("/api/report-button/report", content=_phish()).status_code == 401
    assert c.get("/api/phish-reports", headers={"X-Report-Token": files["token"]}).status_code == 401
    # Junk reporter header: stored as "report button", not as a fake identity.
    c.post("/api/report-button/report", content=_phish(),
           headers={"X-Report-Token": files["token"], "X-Reporter": "<script>"})
    assert c.get("/api/phish-reports", headers=mh).json()[0]["reported_by"] == "report button"


def test_new_token_replaces_old_and_revoke(rb):
    owner, c, oh, mh, files = rb
    new = c.post("/api/report-button/token", headers=oh).json()["token"]
    h = lambda t: {"X-Report-Token": t}  # noqa: E731
    assert c.post("/api/report-button/report", content=_phish(), headers=h(files["token"])).status_code == 401
    assert c.post("/api/report-button/report", content=_phish(), headers=h(new)).status_code == 201
    assert c.delete("/api/report-button/token", headers=oh).status_code == 204
    assert c.post("/api/report-button/report", content=_phish(), headers=h(new)).status_code == 401


def test_tokens_are_per_company(rb, db):  # noqa: F811
    owner, c, oh, mh, files = rb
    other = make_user(db, "x@other.com", company="Other")
    xh = {"Authorization": f"Bearer {login_as(c, other, keep_cookies=False)['access_token']}"}
    c.post("/api/report-button/report", content=_phish(), headers={"X-Report-Token": files["token"]})
    assert c.get("/api/phish-reports", headers=xh).json() == []


def test_add_in_files(rb, db):  # noqa: F811
    owner, c, oh, mh, files = rb
    root = ET.fromstring(files["outlook_manifest"].encode())
    ns = {"o": "http://schemas.microsoft.com/office/appforoffice/1.1"}
    src = root.find("o:FormSettings/o:Form/o:DesktopSettings/o:SourceLocation", ns).get("DefaultValue")
    assert src == f"https://phishlens.example/addins/outlook/taskpane.html#t={files['token']}"
    assert db.get(models.Tenant, owner.tenant_id).report_token_hash != files["token"]  # stored hashed
    assert files["token"] in files["gmail_script"] and "https://phishlens.example/api/report-button/report" in files["gmail_script"]
    assert "https://phishlens.example/" in files["gmail_manifest"]
    pane = c.get("/addins/outlook/taskpane.html")
    assert pane.status_code == 200 and "X-Frame-Options" not in pane.headers
    assert "outlook.office.com" in pane.headers["Content-Security-Policy"]
    assert c.get("/dashboard").headers.get("X-Frame-Options") == "DENY"
    png = c.get("/addins/icon-80.png")
    assert png.status_code == 200 and png.content[:8] == b"\x89PNG\r\n\x1a\n"
    assert c.get("/addins/icon-81.png").status_code == 404


def test_tenant_for_ignores_garbage(db):  # noqa: F811
    assert report_button.tenant_for(db, None) is None
    assert report_button.tenant_for(db, "x" * 500) is None
