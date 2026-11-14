"""Microsoft 365 / Google Workspace security check (read-only)."""
import json
import urllib.parse

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt

from app import cloud_posture as cp, models
from app.config import settings
from app.main import app
from tests.conftest import login_as, make_user
from tests.test_phish_reports import db  # noqa: F401  (fixture)

DIR = "11111111-2222-3333-4444-555555555555"


def graph(secure=False):
    def handler(request: httpx.Request):
        u = urllib.parse.unquote(str(request.url))
        if "/oauth2/v2.0/token" in u:
            assert f"/{DIR}/" in u
            return httpx.Response(200, json={"access_token": "t"})
        p = u.split("/v1.0", 1)[-1]
        if p == "/organization":
            return httpx.Response(200, json={"value": [{"displayName": "Acme Corp"}]})
        if p == "/domains":
            return httpx.Response(200, json={"value": [{"id": "acme.com", "isVerified": True},
                                                       {"id": "acme.onmicrosoft.com", "isVerified": True}]})
        if p.startswith("/policies/identitySecurityDefaults"):
            return httpx.Response(200, json={"isEnabled": secure})
        if p.startswith("/identity/conditionalAccess"):
            return httpx.Response(200, json={"value": []})
        if p.startswith("/policies/authorizationPolicy"):
            grants = [] if secure else ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
            return httpx.Response(200, json={"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": grants}})
        if p.startswith("/directoryRoles?"):
            return httpx.Response(200, json={"value": [{"id": "role1"}]})
        if p.startswith("/directoryRoles/role1/members"):
            n = 2 if secure else 6
            return httpx.Response(200, json={"value": [{"userPrincipalName": f"a{i}@acme.com"} for i in range(n)]})
        if p.startswith("/reports/authenticationMethods"):
            return httpx.Response(403)  # needs Entra ID P1: skipped
        if p.startswith("/users?"):
            return httpx.Response(200, json={"value": [
                {"id": "u1", "userPrincipalName": "jane@acme.com", "accountEnabled": True, "userType": "Member"},
                {"id": "u2", "userPrincipalName": "bob@acme.com", "accountEnabled": True, "userType": "Member"}]})
        if p == "/users/u1/mailFolders/inbox/messageRules":
            rules = [] if secure else [{"displayName": "x", "isEnabled": True,
                                        "actions": {"forwardTo": [{"emailAddress": {"address": "drop@evil.example"}}]}}]
            return httpx.Response(200, json={"value": rules})
        if p == "/users/u2/mailFolders/inbox/messageRules":
            return httpx.Response(200, json={"value": [{"displayName": "team", "isEnabled": True, "actions": {
                "forwardTo": [{"emailAddress": {"address": "boss@acme.com"}}]}}]})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_m365_findings(monkeypatch):
    monkeypatch.setattr(settings, "M365_CLIENT_ID", "cid")
    monkeypatch.setattr(settings, "M365_CLIENT_SECRET", "sec")
    r = cp.m365_checks(DIR, transport=graph())
    by = {c["key"]: c for c in r["checks"]}
    assert r["organization"] == "Acme Corp" and "acme.com" in r["domains"]
    assert by["m365_mfa"]["status"] == "fail" and by["m365_legacy"]["status"] == "warn"
    assert by["m365_admins"]["status"] == "warn" and by["m365_consent"]["status"] == "fail"
    assert by["m365_forwarding"]["status"] == "fail" and "drop@evil.example" in by["m365_forwarding"]["issues"][0]
    assert "boss@acme.com" not in str(by["m365_forwarding"])  # internal forwarding is fine
    assert "m365_mfa_registered" not in by  # no P1 licence: skipped, not failed
    ok = {c["key"]: c["status"] for c in cp.m365_checks(DIR, transport=graph(secure=True))["checks"]}
    assert set(ok.values()) == {"pass"}


def _sa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"client_email": "pl@proj.iam.gserviceaccount.com", "client_id": "1234567890", "private_key": pem}, pub


def test_gws_findings(monkeypatch):
    sa, pub = _sa()
    monkeypatch.setattr(settings, "GOOGLE_WORKSPACE_SERVICE_ACCOUNT", json.dumps(sa))
    subjects = []

    def handler(request: httpx.Request):
        u = str(request.url)
        if u == cp.GOOGLE_TOKEN:
            body = urllib.parse.parse_qs(request.content.decode())
            claims = jwt.decode(body["assertion"][0], pub, algorithms=["RS256"], audience=cp.GOOGLE_TOKEN)
            subjects.append((claims["sub"], claims["scope"]))
            return httpx.Response(200, json={"access_token": "tok-" + claims["sub"]})
        if "/domains" in u:
            return httpx.Response(200, json={"domains": [{"domainName": "acme.com", "verified": True}]})
        if "/users?" in u:
            return httpx.Response(200, json={"users": [
                {"primaryEmail": "admin@acme.com", "isAdmin": True, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": False},
                {"primaryEmail": "jane@acme.com", "isAdmin": False, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": False}]})
        if "autoForwarding" in u:
            who = request.headers["Authorization"].split("tok-")[1]
            return httpx.Response(200, json={"enabled": who == "jane@acme.com", "emailAddress": "jane@gmail.com"})
        return httpx.Response(404)
    r = cp.gws_checks("acme.com", "admin@acme.com", transport=httpx.MockTransport(handler))
    by = {c["key"]: c for c in r["checks"]}
    assert by["gws_2sv"]["status"] == "fail" and "admin@acme.com" in by["gws_2sv"]["issues"][0]
    assert by["gws_admins"]["status"] == "warn" and by["gws_admin_2sv"]["status"] == "fail"
    assert by["gws_forwarding"]["issues"] == ["jane@acme.com → jane@gmail.com"]
    assert subjects[0] == ("admin@acme.com", " ".join(cp.GOOGLE_SCOPES))
    assert ("jane@acme.com", cp.GMAIL_SCOPE) in subjects  # mail settings only, per user
    assert cp.gws_client_id() == "1234567890"


@pytest.fixture()
def owner(db, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "M365_CLIENT_ID", "cid")
    monkeypatch.setattr(settings, "M365_CLIENT_SECRET", "sec")
    return make_user(db, "boss@acme.com", company="Acme")


def test_m365_consent_flow(owner, db, monkeypatch):  # noqa: F811
    c = TestClient(app)
    login_as(c, owner)
    r = c.post("/api/posture/m365/connect", headers={"X-CSRF-Token": "test-csrf"})
    url = r.json()["url"]
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert url.startswith(cp.MS_LOGIN) and q["client_id"] == ["cid"]
    cookie = r.cookies.get("posture_state")
    ran = []
    monkeypatch.setattr(cp, "run", lambda db, t, **k: ran.append(t.id))
    c.cookies.set("posture_state", cookie, domain="testserver.local", path="/posture/m365/callback")
    bad = c.get(f"/posture/m365/callback?tenant={DIR}&state=nope&admin_consent=True", follow_redirects=False)
    assert "posture=expired" in bad.headers["location"]
    c.cookies.set("posture_state", cookie, domain="testserver.local", path="/posture/m365/callback")
    ok = c.get(f"/posture/m365/callback?tenant={DIR}&state={q['state'][0]}&admin_consent=True", follow_redirects=False)
    assert "posture=connected" in ok.headers["location"] and ran
    assert db.get(models.Tenant, owner.tenant_id).posture["m365"]["directory"] == DIR


def test_api_and_member_read_only(owner, db):  # noqa: F811
    c = TestClient(app)
    member = make_user(db, "staff@acme.com", role="member", tenant=owner.tenant, mfa=False)
    mh = {"Authorization": f"Bearer {login_as(c, member, keep_cookies=False)['access_token']}"}
    d = c.get("/api/posture", headers=mh).json()
    assert d["m365"]["configured"] is True and d["m365"]["connected"] is False and d["gws"]["configured"] is False
    assert c.post("/api/posture/m365/connect", headers=mh).status_code == 403
    assert c.post("/api/posture/run", headers=mh).status_code == 403
    oh = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    assert c.put("/api/posture/gws", headers=oh, json={"domain": "acme.com", "admin_email": "a@acme.com"}).status_code == 400


def test_errors_are_kept_and_weekly(owner, db, monkeypatch):  # noqa: F811
    t = db.get(models.Tenant, owner.tenant_id)
    cp.m365_connect(db, t, DIR)
    refused = httpx.MockTransport(lambda r: httpx.Response(400))
    p = cp.run(db, t, transport=refused)
    assert "admin consent" in p["m365"]["error"]
    assert cp.run_all(db)["checked"] == 0  # just checked
    with pytest.raises(cp.PostureError):
        cp.m365_connect(db, t, "not-a-guid")
