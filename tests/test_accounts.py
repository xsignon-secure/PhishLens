"""Admin-created accounts: provisioning, sign-in steps, company isolation,
step-up, sessions and the platform admin."""
from datetime import datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app import credentials, mailer, models, security
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from tests.conftest import ADMIN_PASSWORD, TEST_PASSWORD, login_as, make_user, totp_now

NEW_PASSWORD = "plum orchard lantern 42"


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
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [])
    return TestClient(app)


@pytest.fixture()
def outbox(monkeypatch):
    """Every message handed to a mail server: (server config, message)."""
    sent = []
    monkeypatch.setattr(mailer, "deliver", lambda cfg, msg: sent.append((cfg, msg)))
    return sent


def _smtp(db, tenant, host):
    from app import crypto
    tenant.smtp = {"host": host, "port": 587, "security": "starttls", "username": "u",
                   "password": crypto.encrypt("smtp-secret"), "from_address": f"it@{host}", "from_name": None}
    db.commit()


def _two_companies(db):
    a_owner = make_user(db, "owner@a.com", company="A")
    b_owner = make_user(db, "owner@b.com", company="B")
    _smtp(db, a_owner.tenant, "smtp.a.com")
    _smtp(db, b_owner.tenant, "smtp.b.com")
    return a_owner, b_owner


def _temp_from(msg) -> str:
    line = next(line for line in msg.get_content().splitlines() if line.startswith("Temporary password:"))
    return line.split(":", 1)[1].strip()


def _new_client():
    return TestClient(app)


# ------------------------------------------------------------------ provisioning
def test_admin_creates_user_who_signs_in_with_emailed_temp_password(client, db, outbox):
    a_owner, _ = _two_companies(db)
    login_as(client, a_owner)
    r = client.post("/api/users", json={"email": "Jane@A.com", "full_name": "Jane", "role": "member"},
                    headers={"X-CSRF-Token": "test-csrf"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending" and body["temporary_password"]
    # Sent from company A's own server, to the new user only.
    (cfg, msg), = outbox
    assert cfg["host"] == "smtp.a.com" and msg["From"] == "it@smtp.a.com" and msg["To"] == "jane@a.com"
    temp = _temp_from(msg)
    assert temp == body["temporary_password"]
    listed = client.get("/api/users").json()
    assert next(u for u in listed if u["email"] == "jane@a.com")["credentials_status"] == "sent"
    assert all(k not in u for u in listed for k in ("password_hash", "temporary_password"))

    jane = _new_client()
    r = jane.post("/api/auth/login", json={"email": "jane@a.com", "password": temp}).json()
    assert r["next"] == "change_password" and "access_token" not in r
    # The step token opens nothing but the password change.
    assert jane.get("/api/monitors", headers={"Authorization": "Bearer " + r["step_token"]}).status_code == 401
    bad = jane.post("/api/auth/first-password", json={"step_token": r["step_token"], "password": temp})
    assert bad.status_code == 400
    assert jane.post("/api/auth/first-password", json={"step_token": r["step_token"], "password": "short"}).status_code == 400
    done = jane.post("/api/auth/first-password", json={"step_token": r["step_token"], "password": NEW_PASSWORD}).json()
    assert done["next"] == "done" and done["user"]["role"] == "member"
    assert jane.get("/api/monitors").status_code == 200
    # The temporary password worked once.
    assert _new_client().post("/api/auth/login", json={"email": "jane@a.com", "password": temp}).status_code == 401
    assert _new_client().post("/api/auth/login", json={"email": "jane@a.com", "password": NEW_PASSWORD}).json()["next"] == "done"


def test_credential_job_only_reads_its_own_company(db, outbox):
    a_owner, b_owner = _two_companies(db)
    user = make_user(db, "x@a.com", "member", a_owner.tenant, mfa=False)
    credentials.deliver(user.id, b_owner.tenant_id, "Temp-Password-123")  # wrong company: nothing sent
    assert outbox == []
    credentials.deliver(user.id, a_owner.tenant_id, "Temp-Password-123")
    assert [cfg["host"] for cfg, _ in outbox] == ["smtp.a.com"]


def test_without_any_mail_server_the_admin_hands_over_the_password(client, db, outbox):
    owner = make_user(db)
    login_as(client, owner)
    r = client.post("/api/users", json={"email": "m@x.com"}, headers={"X-CSRF-Token": "test-csrf"})
    assert r.status_code == 201 and outbox == []
    assert r.json()["credentials_status"] == "manual"  # the page says so straight away
    assert client.get("/api/users").json()[-1]["credentials_status"] == "manual"


def test_failed_delivery_keeps_the_account_and_says_why(client, db, monkeypatch):
    owner = make_user(db)
    _smtp(db, owner.tenant, "smtp.x.com")

    def boom(cfg, msg):
        raise mailer.SmtpError("The mail server refused the username or password")
    monkeypatch.setattr(mailer, "deliver", boom)
    login_as(client, owner)
    assert client.post("/api/users", json={"email": "m@x.com"}, headers={"X-CSRF-Token": "test-csrf"}).status_code == 201
    u = client.get("/api/users").json()[-1]
    assert u["credentials_status"] == "failed" and "refused" in u["credentials_error"]


def test_temp_password_expires(client, db, outbox):
    owner = make_user(db)
    login_as(client, owner)
    temp = client.post("/api/users", json={"email": "m@x.com", "send_email": False},
                       headers={"X-CSRF-Token": "test-csrf"}).json()["temporary_password"]
    user = db.query(models.User).filter_by(email="m@x.com").one()
    user.temp_password_expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    r = _new_client().post("/api/auth/login", json={"email": "m@x.com", "password": temp})
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_resend_makes_a_new_password_and_ends_sessions(client, db, outbox):
    owner = make_user(db)
    _smtp(db, owner.tenant, "smtp.x.com")
    member = make_user(db, "m@x.com", "member", owner.tenant, mfa=False)
    m = _new_client()
    login_as(m, member)
    assert m.get("/api/monitors").status_code == 200
    login_as(client, owner)
    first = client.post(f"/api/users/{member.id}/resend", headers={"X-CSRF-Token": "test-csrf"}).json()["temporary_password"]
    second = client.post(f"/api/users/{member.id}/resend", headers={"X-CSRF-Token": "test-csrf"}).json()["temporary_password"]
    assert first != second and len(outbox) == 2
    assert m.get("/api/monitors").status_code == 401  # signed out
    assert _new_client().post("/api/auth/login", json={"email": "m@x.com", "password": first}).status_code == 401
    assert _new_client().post("/api/auth/login", json={"email": "m@x.com", "password": TEST_PASSWORD}).status_code == 401
    assert _new_client().post("/api/auth/login", json={"email": "m@x.com", "password": second}).json()["next"] == "change_password"


def test_csv_import_reports_each_row(client, db, outbox):
    owner = make_user(db)
    _smtp(db, owner.tenant, "smtp.x.com")
    make_user(db, "taken@x.com", "member", owner.tenant, mfa=False)
    login_as(client, owner)
    csv = "email,name,role\na@x.com,Ann,member\nnot-an-email,,\ntaken@x.com,,member\nb@x.com,Bob,admin\nc@x.com,,boss\n"
    r = client.post("/api/users/import", json={"csv": csv}, headers={"X-CSRF-Token": "test-csrf"}).json()
    assert r["created"] == 2 and r["failed"] == 3
    assert [row["ok"] for row in r["rows"]] == [True, False, False, True, False]
    assert {msg["To"] for _, msg in outbox} == {"a@x.com", "b@x.com"}


# ------------------------------------------------------------------ roles
def test_member_has_no_admin_endpoints(client, db):
    owner = make_user(db)
    member = make_user(db, "m@x.com", "member", owner.tenant, mfa=False)
    login_as(client, member)
    h = {"X-CSRF-Token": "test-csrf"}
    assert client.post("/api/users", json={"email": "n@x.com"}, headers=h).status_code == 403
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/team/smtp").status_code == 403
    assert client.get("/api/team/export").status_code == 403
    assert client.get("/api/monitors").status_code == 200


def test_admins_manage_members_only(client, db, outbox):
    owner = make_user(db)
    admin = make_user(db, "admin@x.com", "admin", owner.tenant)
    other_admin = make_user(db, "admin2@x.com", "admin", owner.tenant)
    member = make_user(db, "m@x.com", "member", owner.tenant, mfa=False)
    login_as(client, admin)
    h = {"X-CSRF-Token": "test-csrf"}
    assert client.post("/api/users", json={"email": "n@x.com", "role": "admin"}, headers=h).status_code == 403
    assert client.post("/api/users", json={"email": "n@x.com", "role": "member"}, headers=h).status_code == 201
    for target in (owner, other_admin):
        assert client.post(f"/api/users/{target.id}/suspend", headers=h).status_code == 403
    assert client.patch(f"/api/users/{member.id}", json={"role": "admin"}, headers=h).status_code == 403
    assert client.post(f"/api/users/{member.id}/suspend", headers=h).status_code == 200
    assert client.post(f"/api/users/{admin.id}/suspend", headers=h).status_code == 400  # not yourself


def test_role_change_and_suspension_end_sessions(client, db):
    owner = make_user(db)
    member = make_user(db, "m@x.com", "member", owner.tenant, mfa=False)
    m = _new_client()
    login_as(m, member)
    login_as(client, owner)
    h = {"X-CSRF-Token": "test-csrf"}
    assert client.patch(f"/api/users/{member.id}", json={"role": "admin"}, headers=h).json()["role"] == "admin"
    assert m.get("/api/monitors").status_code == 401
    login_as(m, member)
    assert client.post(f"/api/users/{member.id}/suspend", headers=h).status_code == 200
    assert m.get("/api/monitors").status_code == 401
    r = _new_client().post("/api/auth/login", json={"email": "m@x.com", "password": TEST_PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid email or password"


# ------------------------------------------------------------------ isolation
def test_admin_cannot_reach_another_companys_users_or_data(client, db, outbox):
    a_owner, b_owner = _two_companies(db)
    b_member = make_user(db, "m@b.com", "member", b_owner.tenant, mfa=False)
    b = _new_client()
    login_as(b, b_owner)
    mid = b.post("/api/monitors", json={"domain": "b-only.com"}, headers={"X-CSRF-Token": "test-csrf"}).json()["id"]

    login_as(client, a_owner)
    h = {"X-CSRF-Token": "test-csrf"}
    assert [u["email"] for u in client.get("/api/users").json()] == ["owner@a.com"]
    for path in ("suspend", "resend", "reset-mfa"):
        assert client.post(f"/api/users/{b_member.id}/{path}", headers=h).status_code == 404
    assert client.patch(f"/api/users/{b_member.id}", json={"role": "admin"}, headers=h).status_code == 404
    assert client.delete(f"/api/users/{b_member.id}", headers=h).status_code == 404
    assert client.get("/api/monitors").json() == []
    assert client.delete(f"/api/monitors/{mid}", headers=h).status_code == 404
    assert client.get(f"/api/monitors/{mid}/changes").status_code == 404
    # Company B's mail server and users are untouched.
    db.refresh(b_member)
    assert b_member.status == "active" and outbox == []


def test_tampered_company_in_token_is_refused_and_audited(client, db):
    a_owner, b_owner = _two_companies(db)
    token = login_as(client, a_owner, keep_cookies=False)["access_token"]
    claims = jwt.get_unverified_claims(token)
    forged = jwt.encode({**claims, "tid": b_owner.tenant_id}, "not-the-server-key", algorithm="HS256")
    r = client.get("/api/monitors", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 403
    event = db.query(models.AuditEvent).filter_by(action="security.token_tampered").one()
    assert event.detail["severity"] == "critical" and event.tenant_id == b_owner.tenant_id


def test_token_for_another_company_is_refused_and_session_ended(client, db):
    """Even a correctly signed token is checked against the account's company."""
    a_owner, b_owner = _two_companies(db)
    token = login_as(client, a_owner, keep_cookies=False)["access_token"]
    claims = jwt.get_unverified_claims(token)
    resigned = jwt.encode({**claims, "tid": b_owner.tenant_id}, settings.SECRET_KEY, algorithm="HS256")
    assert client.get("/api/monitors", headers={"Authorization": f"Bearer {resigned}"}).status_code == 403
    assert db.query(models.AuditEvent).filter_by(action="security.cross_tenant").one().detail["severity"] == "critical"
    assert client.get("/api/monitors", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_smtp_password_is_write_only(client, db):
    owner = make_user(db)
    login_as(client, owner)
    h = {"X-CSRF-Token": "test-csrf"}
    cfg = {"host": "smtp.example.com", "port": 587, "username": "it", "password": "hunter2-secret",
           "from_address": "it@example.com", "from_name": "IT"}
    r = client.put("/api/team/smtp", json=cfg, headers=h)
    assert r.status_code == 200 and r.json()["has_password"] is True
    assert "hunter2" not in r.text and "hunter2" not in client.get("/api/team/smtp").text
    assert "hunter2" not in client.get("/api/team/export").text
    db.refresh(owner.tenant)
    assert "hunter2" not in str(owner.tenant.smtp)  # encrypted at rest
    # Blank keeps it; a different server drops it (never sent to a new host).
    assert client.put("/api/team/smtp", json={**cfg, "password": ""}, headers=h).json()["has_password"] is True
    assert client.put("/api/team/smtp", json={**cfg, "password": "", "host": "evil.example.net"},
                      headers=h).json()["has_password"] is False
    assert client.put("/api/team/smtp", json={**cfg, "port": 8080}, headers=h).status_code == 400
    assert client.put("/api/team/smtp", json={**cfg, "host": "localhost"}, headers=h).status_code == 400
    assert client.put("/api/team/smtp", json={**cfg, "extra": 1}, headers=h).status_code == 422


def test_company_mail_server_must_be_public(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with pytest.raises(mailer.SmtpError, match="public"):
        mailer.deliver({"host": "smtp.example.com", "port": 587, "pinned": True,
                        "from_address": "a@example.com"}, None)


# ------------------------------------------------------------------ sign-in
def test_login_failures_look_the_same_and_lock(client, db):
    owner = make_user(db)
    make_user(db, "gone@x.com", "member", owner.tenant, mfa=False).status = "suspended"
    db.commit()
    answers = {client.post("/api/auth/login", json={"email": e, "password": p}).json()["detail"]
               for e, p in (("nobody@x.com", TEST_PASSWORD), ("owner@x.com", "wrong password"),
                            ("gone@x.com", TEST_PASSWORD))}
    assert answers == {"Invalid email or password"}
    for _ in range(4):
        client.post("/api/auth/login", json={"email": "owner@x.com", "password": "wrong password"})
    db.refresh(owner)
    assert owner.locked_until and owner.locked_until > datetime.utcnow()
    from app import deps
    deps._hits.clear()  # past the rate limit: the account lock itself still holds
    r = client.post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD})
    assert r.status_code == 401
    assert db.query(models.AuditEvent).filter_by(action="auth.login_failed").count() >= 5


def test_login_with_authenticator_and_recovery_code(client, db):
    owner = make_user(db)
    r = client.post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD}).json()
    assert r["next"] == "mfa"
    assert client.post("/api/auth/mfa", json={"step_token": r["step_token"], "code": "000000"}).status_code == 401
    ok = client.post("/api/auth/mfa", json={"step_token": r["step_token"], "code": totp_now(owner)})
    assert ok.json()["next"] == "done"
    # The same code can't be used twice.
    r2 = _new_client().post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD}).json()
    assert _new_client().post("/api/auth/mfa", json={"step_token": r2["step_token"], "code": totp_now(owner)}).status_code == 401
    # A recovery code works once.
    db.refresh(owner)
    code = security.new_recovery_codes(owner)[0]
    db.commit()
    for expected in (200, 401):
        r3 = _new_client().post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD}).json()
        assert _new_client().post("/api/auth/mfa", json={"step_token": r3["step_token"], "code": code}).status_code == expected


def test_admins_must_set_up_an_authenticator(client, db):
    owner = make_user(db, mfa=False)
    r = client.post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD}).json()
    assert r["next"] == "done" and r["user"]["mfa_required"] and not r["user"]["mfa_enabled"]
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    blocked = client.get("/api/monitors")
    assert blocked.status_code == 403 and blocked.json()["detail"] == "mfa_setup_required"
    setup = client.post("/api/auth/mfa/setup", headers=h).json()
    assert setup["qr_svg"].startswith("<svg")
    code = pyotp.TOTP(setup["secret"]).now()
    on = client.post("/api/auth/mfa/enable", json={"code": code}, headers=h).json()
    assert len(on["recovery_codes"]) == 10
    assert client.get("/api/monitors").status_code == 200
    db.refresh(owner)
    assert all(c not in str(owner.recovery_codes) for c in on["recovery_codes"])  # only hashes stored
    assert client.post("/api/auth/mfa/disable", json={"code": on["recovery_codes"][0]}, headers=h).status_code == 400


def test_authenticator_setup_keeps_its_key_until_confirmed(client, db):
    make_user(db, mfa=False)
    client.post("/api/auth/login", json={"email": "owner@x.com", "password": TEST_PASSWORD})
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    first = client.post("/api/auth/mfa/setup", headers=h).json()
    # A reload or a mistyped code must not swap the key the phone scanned.
    assert client.post("/api/auth/mfa/enable", json={"code": "000000"}, headers=h).status_code == 400
    again = client.post("/api/auth/mfa/setup", headers=h).json()
    assert again["secret"] == first["secret"]
    code = pyotp.TOTP(first["secret"]).now()
    assert client.post("/api/auth/mfa/enable", json={"code": code}, headers=h).status_code == 200


def test_sensitive_changes_need_a_fresh_code(client, db):
    owner = make_user(db)
    login_as(client, owner, mfa=False)  # signed in a while ago, no recent code
    h = {"X-CSRF-Token": "test-csrf"}
    r = client.post("/api/users", json={"email": "m@x.com"}, headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "step_up_required"
    assert client.get("/api/team/export").json()["detail"] == "step_up_required"
    assert client.post("/api/auth/step-up", json={"code": "123456"}, headers=h).status_code == 401
    assert client.post("/api/auth/step-up", json={"code": totp_now(owner)}, headers=h).status_code == 200
    assert client.post("/api/users", json={"email": "m@x.com", "send_email": False}, headers=h).status_code == 201
    # API keys can't make these changes at all.
    key = client.post("/api/team/keys", json={"name": "k"}, headers=h).json()["api_key"]
    assert _new_client().post("/api/users", json={"email": "n@x.com"}, headers={"X-API-Key": key}).status_code == 403


def test_api_key_stops_with_its_user(client, db):
    owner = make_user(db)
    admin = make_user(db, "admin@x.com", "admin", owner.tenant)
    login_as(client, admin)
    key = client.post("/api/team/keys", json={"name": "k"}, headers={"X-CSRF-Token": "test-csrf"}).json()["api_key"]
    assert _new_client().get("/api/monitors", headers={"X-API-Key": key}).status_code == 200
    login_as(client, owner)
    client.post(f"/api/users/{admin.id}/suspend", headers={"X-CSRF-Token": "test-csrf"})
    assert _new_client().get("/api/monitors", headers={"X-API-Key": key}).status_code == 401


# ------------------------------------------------------------------ sessions
def test_expired_access_token_is_renewed_and_replay_ends_the_session(client, db, monkeypatch):
    owner = make_user(db)
    monkeypatch.setattr(settings, "ACCESS_TOKEN_MINUTES", -1)  # born expired
    login_as(client, owner)
    old_refresh = client.cookies.get("refresh_token")
    monkeypatch.setattr(settings, "ACCESS_TOKEN_MINUTES", 15)
    assert client.get("/api/monitors").status_code == 200  # renewed on the way
    assert client.cookies.get("refresh_token") != old_refresh
    assert client.get("/api/monitors").status_code == 200
    # The old refresh token, used again after the grace period: replay.
    row = db.query(models.UserSession).one()
    row.rotated_at = datetime.utcnow() - timedelta(minutes=5)
    db.commit()
    thief = _new_client()
    thief.cookies.set("refresh_token", old_refresh)
    assert thief.get("/api/monitors").status_code == 401
    assert db.query(models.AuditEvent).filter_by(action="security.refresh_token_replay").one().detail["severity"] == "critical"
    db.refresh(row)
    assert row.revoked_reason == "refresh_replay"


def test_idle_session_ends(client, db):
    owner = make_user(db)
    login_as(client, owner)
    row = db.query(models.UserSession).one()
    row.last_used_at = datetime.utcnow() - timedelta(minutes=settings.SESSION_IDLE_MINUTES + 1)
    db.commit()
    assert client.get("/api/monitors").status_code == 401


def test_sessions_list_and_sign_out_one_device(client, db):
    owner = make_user(db)
    other = _new_client()
    login_as(other, owner)
    login_as(client, owner)
    rows = client.get("/api/auth/sessions").json()
    assert len(rows) == 2 and sum(r["current"] for r in rows) == 1
    other_id = next(r["id"] for r in rows if not r["current"])
    assert client.delete(f"/api/auth/sessions/{other_id}", headers={"X-CSRF-Token": "test-csrf"}).status_code == 200
    assert other.get("/api/monitors").status_code == 401
    assert client.get("/api/monitors").status_code == 200


def test_password_change_signs_out_other_devices(client, db):
    owner = make_user(db)
    other = _new_client()
    login_as(other, owner)
    login_as(client, owner)
    h = {"X-CSRF-Token": "test-csrf"}
    assert client.post("/api/auth/password", json={"current_password": "nope", "new_password": NEW_PASSWORD}, headers=h).status_code == 400
    r = client.post("/api/auth/password", json={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD}, headers=h)
    assert r.json()["other_sessions_ended"] == 1
    assert other.get("/api/monitors").status_code == 401 and client.get("/api/monitors").status_code == 200


def test_no_signup_or_invitation_routes(client, db):
    for path in ("/api/auth/signup", "/api/team/invite", "/api/auth/password/forgot"):
        assert client.post(path, json={}).status_code in (404, 405)
    assert client.get("/signup").status_code == 404


# ------------------------------------------------------------------ platform admin
def test_platform_admin_creates_companies_but_sees_no_company_data(client, db, outbox, monkeypatch):
    monkeypatch.setattr(mailer, "is_configured", lambda: True)  # server-wide SMTP for new companies
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.server.example")
    monkeypatch.setattr(settings, "SMTP_FROM", "noreply@server.example")
    assert client.post("/api/platform/login", json={"password": "nope"}).status_code == 401
    assert client.get("/api/platform/companies").status_code == 401
    assert client.post("/api/platform/login", json={"password": ADMIN_PASSWORD}).status_code == 200
    h = {"X-CSRF-Token": client.cookies.get("csrf_token")}
    r = client.post("/api/platform/companies", json={"name": "Acme", "owner_email": "boss@acme.com"}, headers=h)
    assert r.status_code == 201 and r.json()["owners"][0]["role"] == "owner"
    (cfg, msg), = outbox
    assert msg["To"] == "boss@acme.com" and cfg["host"] == "smtp.server.example"
    assert client.get("/api/monitors").status_code == 401  # the platform cookie opens no company
    tid = r.json()["id"]
    assert client.post(f"/api/platform/companies/{tid}/suspend", headers=h).json()["status"] == "suspended"
    temp = _temp_from(msg)
    assert _new_client().post("/api/auth/login", json={"email": "boss@acme.com", "password": temp}).status_code == 401
    client.post(f"/api/platform/companies/{tid}/reactivate", headers=h)
    assert _new_client().post("/api/auth/login", json={"email": "boss@acme.com", "password": temp}).json()["next"] == "change_password"
    # The platform page also gives older companies their first owner.
    old = models.Tenant(name="Before accounts")
    db.add(old)
    db.commit()
    assert client.post(f"/api/platform/companies/{old.id}/owners", json={"email": "first@old.com"}, headers=h).status_code == 201


def test_platform_is_off_without_admin_password(client, db, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "")
    assert client.post("/api/platform/login", json={"password": "x"}).status_code == 503
