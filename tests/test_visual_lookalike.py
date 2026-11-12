"""Visual lookalike check: is a registered lookalike showing a copy of the site?"""
import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app import models
from app.config import settings
from app.main import app
from app.scanner import engine, lookalike, visual
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)


def _png(color, size=64, shape="circle"):
    img = Image.new("RGB", (size, size), "white")
    d = ImageDraw.Draw(img)
    if shape == "circle":
        d.ellipse((8, 8, size - 8, size - 8), fill=color)
    else:
        d.rectangle((0, size // 2, size, size), fill=color)
        d.polygon([(0, 0), (size, 0), (0, size // 2)], fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


LOGO = _png("navy")


def _resized(data, size):
    buf = io.BytesIO()
    Image.open(io.BytesIO(data)).resize((size, size)).save(buf, "JPEG", quality=80)
    return buf.getvalue()


LOGO_BIG = _resized(LOGO, 200)  # same logo, resized and re-encoded
OTHER = _png("orange", shape="other")
BRAND = '<html><title>Acme Corp – Sign in</title><link rel="icon" href="/fav.png"><body>Welcome to Acme</body></html>'
COPY = ('<html><title>Acme Corp - Sign in</title><link rel="icon" href="/i.png"><body>Acme account'
        '<form><input type="password" name="p"></form></body></html>')
PARKED = '<html><title>This domain is for sale</title><body>Buy this domain</body></html>'


@pytest.fixture()
def web(monkeypatch):
    sites = {"https://acme.com/": BRAND, "https://acme.com/fav.png": LOGO,
             "https://acrne.com/": COPY, "https://acrne.com/i.png": LOGO_BIG,
             "https://acme.net/": PARKED, "https://acme.net/favicon.ico": OTHER}
    fetched = []

    def fetch(url, timeout, limit=4096):
        fetched.append(url)
        if url not in sites:
            raise ValueError("no")
        body = sites[url]
        return 200, body.encode() if isinstance(body, str) else body
    monkeypatch.setattr(visual.net, "safe_fetch_head", fetch)
    monkeypatch.setattr(settings, "VISUAL_LOOKALIKE_CHECK", True)
    return fetched


def test_image_hash_survives_resizing():
    assert visual.distance(visual.image_hash(LOGO), visual.image_hash(LOGO_BIG)) <= 6
    assert visual.distance(visual.image_hash(LOGO), visual.image_hash(OTHER)) > 12
    assert visual.image_hash(b"not an image") is None


def test_copy_of_the_site_is_impersonating(web):
    r = visual.check("acme.com", "acrne.com", "Acme Corp")
    assert r["verdict"] == "impersonating" and r["score"] >= visual.IMPERSONATING and r["login_form"]
    text = " ".join(r["reasons"])
    assert "logo or site icon" in text and "page title" in text and "Asks for a password" in text


def test_parked_page_is_different(web):
    r = visual.check("acme.com", "acme.net", "Acme Corp")
    assert r["verdict"] == "different" and r["score"] < visual.SUSPICIOUS


def test_no_site(web):
    assert visual.check("acme.com", "acme.org")["verdict"] == "no_site"


def test_scheduled_check_alerts_once_and_only_when_on(web, monkeypatch, db):  # noqa: F811
    owner = make_user(db, "boss@acme.com", company="Acme Corp")
    m = models.Monitor(tenant_id=owner.tenant_id, domain="acme.com", lookalikes=[])
    db.add(m)
    db.commit()
    reg = [{"domain": "acrne.com", "has_web": True, "mx": [], "technique": "homoglyph", "risk": "medium"},
           {"domain": "acme.net", "has_web": True, "mx": [], "technique": "tld", "risk": "medium"},
           {"domain": "acme.org", "has_web": False, "mx": [], "technique": "tld", "risk": "low"}]
    monkeypatch.setattr(lookalike, "scan", lambda d: {"domain": d, "checked": 3, "registered": reg, "high_risk": 0})
    alerts = engine.check_monitor_lookalikes(m)
    kinds = [a.kind for a in alerts]
    assert kinds.count("lookalike_impersonating") == 1 and "acrne.com" in alerts[-1].message
    assert set(m.lookalike_visual) == {"acrne.com", "acme.net"}  # no website: not fetched
    # Next run inside a week: nothing refetched, no repeat alert.
    web.clear()
    assert not [a for a in engine.check_monitor_lookalikes(m) if a.kind == "lookalike_impersonating"]
    assert web == []
    # Turned off: nothing is fetched at all.
    monkeypatch.setattr(settings, "VISUAL_LOOKALIKE_CHECK", False)
    m.lookalike_visual = None
    engine.check_monitor_lookalikes(m)
    assert web == [] and m.lookalike_visual is None


def test_on_demand_compare_endpoint(web, monkeypatch, db):  # noqa: F811
    owner = make_user(db, "boss@acme.com", company="Acme Corp")
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="acme.com"))
    db.commit()
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    r = c.post("/api/tools/lookalikes/visual", headers=h, json={"domain": "acme.com", "lookalike": "acrne.com"})
    assert r.status_code == 200 and r.json()["verdict"] == "impersonating"
    assert c.get("/api/monitors", headers=h).json()[0]["impersonating"] == 1
    # Only lookalike spellings: it can't be used to fetch any website.
    r = c.post("/api/tools/lookalikes/visual", headers=h, json={"domain": "acme.com", "lookalike": "example.org"})
    assert r.status_code == 400
    monkeypatch.setattr(settings, "VISUAL_LOOKALIKE_CHECK", False)
    r = c.post("/api/tools/lookalikes/visual", headers=h, json={"domain": "acme.com", "lookalike": "acrne.com"})
    assert r.status_code == 400 and "turned off" in r.json()["detail"]


def test_screenshots_need_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "VISUAL_SCREENSHOTS", False)
    assert visual._screenshot_hash("https://acme.com/") is None
