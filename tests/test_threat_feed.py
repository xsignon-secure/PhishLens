"""Threat feed: STIX 2.1 indicators over TAXII 2.1 and plain downloads."""
import base64
import hashlib
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app import models, threat_feed
from app.config import settings
from app.main import app
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)

COL = threat_feed.COLLECTION_ID
TAXII = "application/taxii+json;version=2.1"


def _key(db, user, raw="plk_feedkey_0123456789abcdef"):
    db.add(models.ApiKey(tenant_id=user.tenant_id, user_id=user.id, name="SIEM",
                         key_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:12]))
    db.commit()
    return raw


def _basic(key):
    return {"Authorization": "Basic " + base64.b64encode(f"sentinel:{key}".encode()).decode(),
            "Accept": TAXII}


def _seed(db, tenant_id):
    m = models.Monitor(tenant_id=tenant_id, domain="acme.com",
                       lookalikes=["acme-login.com", "acrne.com"],
                       lookalike_visual={"acme-login.com": {"verdict": "impersonating", "login_form": True}},
                       ct_state={"lookalike_max_id": {"acme-login.com": 99}})
    db.add(m)
    db.add(models.PhishReport(tenant_id=tenant_id, sender="IT Desk <it@evil-desk.example>", subject="Reset",
                              verdict="dangerous", score=100, status="confirmed", links=[
                                  {"url": "https://evil-desk.example/login?x='1'", "domain": "evil-desk.example",
                                   "verdict": "dangerous"},
                                  {"url": "https://www.microsoft.com/", "domain": "microsoft.com",
                                   "verdict": "no known threat"},
                                  {"url": "https://portal.acme.com/", "domain": "acme.com", "verdict": "dangerous"}]))
    db.add(models.PhishReport(tenant_id=tenant_id, sender="x@nice.example", subject="Hi", verdict="suspicious",
                              score=30, status="new", links=[
                                  {"url": "https://maybe.example/", "domain": "maybe.example",
                                   "verdict": "suspicious"}]))
    db.add(models.Takedown(tenant_id=tenant_id, domain="paypa1-acme.example", url="https://paypa1-acme.example/a",
                           status="sent", draft={}))
    db.commit()
    return m


def test_collect_sources_and_exclusions(db):
    owner = make_user(db, "boss@acme.com")
    _seed(db, owner.tenant_id)
    tenant = db.get(models.Tenant, owner.tenant_id)
    got = threat_feed.collect(db, tenant)
    values = {v for _, v in got}
    assert {"acme-login.com", "acrne.com", "evil-desk.example", "it@evil-desk.example",
            "paypa1-acme.example", "https://paypa1-acme.example/a"} <= values
    # Clean links, the company's own domains, and unconfirmed "suspicious" links stay out.
    assert not values & {"microsoft.com", "acme.com", "https://portal.acme.com/", "maybe.example"}
    assert not any("nice.example" in v for v in values)
    look = got[("domain", "acme-login.com")]
    assert look["malicious"] and look["confidence"] == 95  # impersonating + login + certificate
    weak = got[("domain", "acrne.com")]
    assert not weak["malicious"] and weak["confidence"] == 40


def test_sync_revokes_and_restores(db):
    owner = make_user(db, "boss@acme.com")
    m = _seed(db, owner.tenant_id)
    tenant = db.get(models.Tenant, owner.tenant_id)
    t0 = datetime(2026, 11, 1)
    assert threat_feed.sync(db, tenant, t0)["added"] == 7
    assert threat_feed.sync(db, tenant, t0 + timedelta(hours=1)) == {"added": 0, "changed": 0, "revoked": 0}
    m.lookalikes = ["acme-login.com"]
    db.commit()
    assert threat_feed.sync(db, tenant, t0 + timedelta(hours=2))["revoked"] == 1
    row = db.query(models.ThreatIndicator).filter_by(value="acrne.com").one()
    assert row.revoked and row.modified == t0 + timedelta(hours=2)
    stix = threat_feed.to_stix(tenant, row)
    assert stix["revoked"] is True and stix["id"] == threat_feed.stix_id(tenant.id, "domain", "acrne.com")
    m.lookalikes = ["acme-login.com", "acrne.com"]
    db.commit()
    assert threat_feed.sync(db, tenant, t0 + timedelta(hours=3))["changed"] == 1
    db.refresh(row)
    assert not row.revoked


def test_stix_pattern_escaping(db):
    owner = make_user(db, "boss@acme.com")
    _seed(db, owner.tenant_id)
    tenant = db.get(models.Tenant, owner.tenant_id)
    threat_feed.sync(db, tenant)
    row = db.query(models.ThreatIndicator).filter_by(kind="url", value="https://evil-desk.example/login?x='1'").one()
    obj = threat_feed.to_stix(tenant, row)
    assert obj["pattern"] == "[url:value = 'https://evil-desk.example/login?x=\\'1\\'']"
    assert obj["spec_version"] == "2.1" and obj["indicator_types"] == ["malicious-activity"]
    assert obj["created"].endswith("Z") and obj["valid_from"] == obj["created"]


def test_taxii_flow_with_basic_auth(db):
    owner = make_user(db, "boss@acme.com")
    _seed(db, owner.tenant_id)
    key = _key(db, owner)
    c = TestClient(app)
    assert c.get("/taxii2/", headers={"Accept": TAXII}).status_code == 401
    bad = c.get("/taxii2/", headers=_basic("plk_wrong"))
    assert bad.status_code == 401 and bad.headers["www-authenticate"].startswith("Basic")
    r = c.get("/taxii2/", headers=_basic(key))
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json")
    assert r.json()["api_roots"] == [settings.APP_URL.rstrip("/") + "/taxii2/api/"]
    assert c.get("/taxii2/api/collections/", headers=_basic(key)).json()["collections"][0]["id"] == COL
    assert c.get("/taxii2/api/collections/nope/objects/", headers=_basic(key)).status_code == 404
    page = c.get(f"/taxii2/api/collections/{COL}/objects/?limit=3", headers=_basic(key))
    body = page.json()
    assert body["more"] is True and body["next"] == "3"
    assert body["objects"][0]["type"] == "identity" and len(body["objects"]) == 4
    rest = c.get(f"/taxii2/api/collections/{COL}/objects/?limit=10&next=3", headers=_basic(key)).json()
    assert rest["more"] is False and len(rest["objects"]) == 4
    last = page.headers["x-taxii-date-added-last"]
    assert c.get(f"/taxii2/api/collections/{COL}/objects/?added_after={last}",
                 headers=_basic(key)).json()["objects"] == []
    oid = rest["objects"][0]["id"]
    one = c.get(f"/taxii2/api/collections/{COL}/objects/{oid}/", headers=_basic(key)).json()
    assert one["objects"][0]["id"] == oid
    man = c.get(f"/taxii2/api/collections/{COL}/manifest/", headers=_basic(key)).json()
    assert len(man["objects"]) == 7


def test_tenant_isolation_and_downloads(db):
    owner = make_user(db, "boss@acme.com")
    _seed(db, owner.tenant_id)
    other = make_user(db, "eve@other.com", company="Other")
    other_key = _key(db, other, "plk_otherkey_0123456789abcd")
    c = TestClient(app)
    objs = c.get(f"/taxii2/api/collections/{COL}/objects/", headers=_basic(other_key)).json()["objects"]
    assert [o["type"] for o in objs] == ["identity"]
    assert c.get("/api/threat-feed/domains.txt", headers={"X-API-Key": other_key}).text == ""
    login_as(c, owner)
    s = c.get("/api/threat-feed").json()
    assert s["total"] == 7 and s["by_kind"] == {"domain": 4, "url": 2, "email": 1}
    assert s["taxii"]["collection_id"] == COL
    domains = c.get("/api/threat-feed/domains.txt?min_confidence=80").text.split()
    assert "acme-login.com" in domains and "acrne.com" not in domains
    assert "it@evil-desk.example" in c.get("/api/threat-feed/emails.txt").text
    assert c.get("/api/threat-feed/hosts.txt").status_code == 404
    csv_text = c.get("/api/threat-feed/indicators.csv").text
    assert csv_text.startswith("type,value,confidence")
    bundle = c.get("/api/threat-feed/stix.json").json()
    assert bundle["type"] == "bundle" and len(bundle["objects"]) == 8


def test_plan_gate(db, monkeypatch):
    owner = make_user(db, "boss@acme.com")
    key = _key(db, owner)
    monkeypatch.setattr(settings, "PLANS_ENABLED", True)
    assert TestClient(app).get("/taxii2/", headers=_basic(key)).status_code == 402
