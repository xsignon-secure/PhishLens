"""Enforced 2FA, SCIM provisioning, PGP-encrypted failure reports."""
import shutil
import subprocess
import tempfile

import pyotp
import pytest

from app import models, pgp, security
from tests.test_fill_gaps import _ARF, _auth, _tenant, client, db  # noqa: F401  (fixtures)


def _member(db, tenant, email="m@x.com", password="member-pass-123"):
    u = models.User(tenant_id=tenant.id, email=email, role="member", is_verified=True,
                    password_hash=security.hash_password(password))
    db.add(u)
    db.commit()
    return u


def _login(client, email, password="member-pass-123"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    client.cookies.clear()
    return r.json()


def _enable_mfa(client, h):
    secret = client.post("/api/auth/mfa/setup", headers=h).json()["secret"]
    assert client.post("/api/auth/mfa/verify", headers=h, json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    return secret


# ------------------------------------------------------------------ enforced 2FA
def test_team_can_require_2fa(client, db):
    h = _auth(client, "o@x.com")
    t = _tenant(db, "o@x.com")
    _member(db, t)
    # The owner has to protect their own account first.
    assert client.put("/api/team/security", json={"mfa_required": True}, headers=h).status_code == 400
    _enable_mfa(client, h)
    assert client.put("/api/team/security", json={"mfa_required": True}, headers=h).json() == {"mfa_required": True}

    login = _login(client, "m@x.com")
    assert login["user"]["mfa_setup_required"] is True
    mh = {"Authorization": f"Bearer {login['access_token']}"}
    assert client.get("/api/auth/me", headers=mh).json()["mfa_setup_required"] is True
    client.cookies.set("access_token", login["access_token"])
    assert client.get("/dashboard").status_code == 200  # shows the setup screen
    assert client.get("/overview", follow_redirects=False).headers["location"] == "/dashboard"
    client.cookies.clear()
    blocked = client.get("/api/monitors", headers=mh)
    assert blocked.status_code == 403 and "two-factor" in blocked.json()["detail"]
    _enable_mfa(client, mh)
    assert client.get("/api/monitors", headers=mh).status_code == 200
    assert client.get("/api/auth/me", headers=mh).json()["mfa_setup_required"] is False
    # Nobody can switch it off again while the team requires it.
    r = client.post("/api/auth/mfa/disable", headers=mh, json={"password": "member-pass-123"})
    assert r.status_code == 400
    members = {m["email"]: m["mfa_enabled"] for m in client.get("/api/team/members", headers=h).json()}
    assert members == {"o@x.com": True, "m@x.com": True}


def test_sso_sessions_are_exempt_from_2fa_setup(client, db):
    _auth(client, "o@x.com")
    t = _tenant(db, "o@x.com")
    t.mfa_required = True
    db.commit()
    u = _member(db, t)
    sso = security.create_access_token(user_id=u.id, tenant_id=t.id, sso=True)
    assert client.get("/api/monitors", headers={"Authorization": f"Bearer {sso}"}).status_code == 200
    pw = security.create_access_token(user_id=u.id, tenant_id=t.id)
    assert client.get("/api/monitors", headers={"Authorization": f"Bearer {pw}"}).status_code == 403
    # API keys are created by owners for automation; they aren't held back.
    member_key = models.ApiKey(tenant_id=t.id, user_id=u.id, name="k", prefix="plk_x",
                               key_hash=__import__("hashlib").sha256(b"plk_member").hexdigest())
    db.add(member_key)
    db.commit()
    assert client.get("/api/monitors", headers={"X-API-Key": "plk_member"}).status_code == 200


# ------------------------------------------------------------------ SCIM
def _scim(client, h):
    r = client.post("/api/team/scim/token", headers=h).json()
    assert r["base_url"].endswith("/scim/v2")
    return {"Authorization": f"Bearer {r['token']}"}


def test_scim_user_lifecycle(client, db):
    h = _auth(client, "o@x.com")
    assert client.get("/api/team/scim", headers=h).json()["enabled"] is False
    s = _scim(client, h)
    assert client.get("/api/team/scim", headers=h).json()["enabled"] is True
    assert client.get("/scim/v2/ServiceProviderConfig").json()["patch"]["supported"] is True

    r = client.post("/scim/v2/Users", headers=s, json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "Ann@X.com",
        "name": {"givenName": "Ann"}, "emails": [{"value": "ann@x.com", "primary": True}], "active": True})
    assert r.status_code == 201 and r.headers["content-type"].startswith("application/scim+json")
    ann = r.json()
    assert ann["userName"] == "ann@x.com" and ann["active"] is True
    dup = client.post("/scim/v2/Users", headers=s, json={"userName": "ann@x.com"})
    assert dup.status_code == 409 and dup.json()["scimType"] == "uniqueness"

    found = client.get('/scim/v2/Users?filter=userName eq "ann@x.com"', headers=s).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == ann["id"]
    assert client.get('/scim/v2/Users?filter=externalId eq "abc"', headers=s).json()["totalResults"] == 0
    assert client.get("/scim/v2/Users?filter=name co x", headers=s).status_code == 400
    page = client.get("/scim/v2/Users?startIndex=2&count=1", headers=s).json()
    assert page["totalResults"] == 2 and page["itemsPerPage"] == 1

    # Entra-style PATCH with a string boolean deactivates and signs out.
    u = db.query(models.User).filter_by(email="ann@x.com").one()
    before = u.token_version
    p = client.patch(f"/scim/v2/Users/{ann['id']}", headers=s, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "path": "active", "value": "False"}]})
    assert p.status_code == 200 and p.json()["active"] is False
    db.refresh(u)
    assert not u.is_active and u.token_version == before + 1
    # Okta-style PATCH with a value object reactivates.
    p = client.patch(f"/scim/v2/Users/{ann['id']}", headers=s,
                     json={"Operations": [{"op": "replace", "value": {"active": True}}]})
    assert p.json()["active"] is True
    put = client.put(f"/scim/v2/Users/{ann['id']}", headers=s, json={"userName": "ann2@x.com", "active": True})
    assert put.json()["userName"] == "ann2@x.com"
    assert client.delete(f"/scim/v2/Users/{ann['id']}", headers=s).status_code == 204
    assert client.get(f"/scim/v2/Users/{ann['id']}", headers=s).json()["active"] is False

    # Owners are managed in PhishLens.
    owner = db.query(models.User).filter_by(email="o@x.com").one()
    bad = client.patch(f"/scim/v2/Users/{owner.id}", headers=s,
                       json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert bad.status_code == 400 and bad.json()["scimType"] == "mutability"


def test_scim_auth_and_isolation(client, db):
    h = _auth(client, "o@x.com")
    s = _scim(client, h)
    client.post("/scim/v2/Users", headers=s, json={"userName": "ann@x.com"})
    other = _scim(client, _auth(client, "p@y.com"))
    assert client.get("/scim/v2/Users", headers=other).json()["totalResults"] == 1  # just p@y.com
    ann = db.query(models.User).filter_by(email="ann@x.com").one()
    assert client.get(f"/scim/v2/Users/{ann.id}", headers=other).status_code == 404
    assert client.get("/scim/v2/Users").status_code == 401
    assert client.get("/scim/v2/Users", headers=h).status_code == 401  # a session token isn't a SCIM token
    new = _scim(client, h)  # replaces the old one
    assert client.get("/scim/v2/Users", headers=s).status_code == 401
    client.delete("/api/team/scim/token", headers=h)
    assert client.get("/scim/v2/Users", headers=new).status_code == 401


# ------------------------------------------------------------------ PGP for RUF
@pytest.fixture()
def keypair():
    if not pgp.available():
        pytest.skip("gpg not installed")
    home = tempfile.mkdtemp()
    run = lambda *a, **k: subprocess.run(["gpg", "--homedir", home, "--batch", "--yes", *a],
                                         capture_output=True, check=True, **k)
    run("--passphrase", "", "--quick-gen-key", "Security <sec@x.com>", "default", "default", "never")
    pub = run("--armor", "--export", "sec@x.com").stdout.decode()
    yield pub, lambda blob: run("--decrypt", input=blob.encode()).stdout
    shutil.rmtree(home, ignore_errors=True)


def test_pgp_key_validation(keypair):
    pub, _ = keypair
    info = pgp.inspect("Here's our key:\n" + pub)
    assert len(info["fingerprint"]) == 40 and "Security <sec@x.com>" in info["uids"]
    with pytest.raises(pgp.PgpError):
        pgp.inspect("not a key")
    with pytest.raises(pgp.PgpError):
        pgp.inspect(pub.replace("A", "B", 40))


def test_failure_reports_encrypted_to_team_key(client, db, keypair):
    import json
    pub, decrypt = keypair
    h = _auth(client, "o@x.com")
    assert client.put("/api/team/ruf-pgp", json={"key": "nope"}, headers=h).status_code == 400
    r = client.put("/api/team/ruf-pgp", json={"key": pub}, headers=h)
    assert r.status_code == 200 and r.json()["fingerprint"]
    assert client.post("/api/dmarc/forensic", content=_ARF, headers=h).status_code == 201
    row = client.get("/api/dmarc/forensic", headers=h).json()[0]
    assert row["encrypted"] is True and row["subject"] is None and row["header_from"] is None
    assert row["source_ip"] == "198.51.100.7"  # statistics stay readable
    stored = db.query(models.ForensicReport).one()
    assert "Urgent" not in (stored.subject or "") and "ceo@x.com" not in str(stored.auth_results)
    asc = client.get(f"/api/dmarc/forensic/{row['id']}.asc", headers=h)
    assert asc.status_code == 200 and asc.text.startswith("-----BEGIN PGP MESSAGE-----")
    clear = json.loads(decrypt(asc.text))
    assert clear["subject"] == "Urgent wire transfer" and clear["header_from"] == "ceo@x.com"
    assert client.get(f"/api/dmarc/forensic/{row['id']}.asc", headers=_auth(client, "p@y.com")).status_code == 404


def test_encryption_failure_never_stores_plaintext(client, db, monkeypatch):
    h = _auth(client, "o@x.com")
    t = _tenant(db, "o@x.com")
    t.ruf_pgp_key, t.ruf_pgp_fingerprint = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----", "F" * 40
    db.commit()
    client.post("/api/dmarc/forensic", content=_ARF, headers=h)
    stored = db.query(models.ForensicReport).one()
    assert stored.subject is None and stored.header_from is None and stored.encrypted is None
