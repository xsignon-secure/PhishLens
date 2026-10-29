"""Test isolation.

Point the app at a throwaway SQLite file BEFORE any app module is imported:
the test fixtures drop and recreate every table, and previously did so on
the real ./phishlens.db. Also reset module state that tests mutate.
"""
import os
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="phishlens-tests-")
# TEST_DATABASE_URL runs the suite against e.g. a scratch Postgres database.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_tmpdir}/test.db"
os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD = "test-platform-password"
os.environ["PASSWORD_BREACH_CHECK"] = "false"  # no network in tests
OWNER_EMAIL = "owner@x.com"
TEST_PASSWORD = "correct horse battery staple"

import pytest  # noqa: E402

from app import deps  # noqa: E402
from app.scanner import dns_checks  # noqa: E402

_ORIGINAL_TXT = dns_checks._txt


@pytest.fixture(autouse=True)
def _no_nameserver_lookups(monkeypatch):
    # Scans look up who hosts the domain's DNS; tests never touch the network.
    monkeypatch.setattr("app.scanner.guides.dns_host", lambda domain: None)


@pytest.fixture(autouse=True)
def _reset_module_state():
    deps._hits.clear()
    yield
    dns_checks._txt = _ORIGINAL_TXT  # several tests assign it directly
    deps._hits.clear()


@pytest.fixture(autouse=True)
def _no_dns_snapshots(monkeypatch):
    # Team scans snapshot DNS records for change monitoring; not in tests.
    monkeypatch.setattr("app.scanner.dns_snapshot.snapshot", lambda domain, selector=None: None)


def make_user(db, email=OWNER_EMAIL, role="owner", tenant=None, *, mfa=True, password=TEST_PASSWORD,
              company="Acme"):
    """An active account (with an authenticator app unless mfa=False), in
    `tenant` or a new company."""
    import pyotp

    from app import models, passwords, security
    if tenant is None:
        tenant = models.Tenant(name=company)
        db.add(tenant)
        db.flush()
    user = models.User(tenant_id=tenant.id, email=email, role=role, status="active",
                       password_hash=passwords.hash_password(password), mfa_enabled=mfa)
    if mfa:
        security.set_totp_secret(user, pyotp.random_base32())
    db.add(user)
    db.commit()
    return user


def totp_now(user):
    import pyotp

    from app import security
    return pyotp.TOTP(security.totp_secret(user)).now()


def login_as(client, user, keep_cookies=True, mfa=True):
    """A signed-in session for `user` (a User or its id), as if they had just
    entered their authenticator code (so step-up checks pass)."""
    from app import models, sessions
    from app.database import SessionLocal
    from app.routers.auth import me_out
    user_id = user if isinstance(user, str) else user.id
    db = SessionLocal()
    try:
        u = db.get(models.User, user_id)
        access, refresh, _ = sessions.create(db, u, None, mfa=mfa)
        body = {"access_token": access, "user": me_out(u)}
    finally:
        db.close()
    if keep_cookies:
        # The domain the test client's responses use, so later Set-Cookie
        # headers replace these instead of adding a second copy.
        client.cookies.clear()
        for name, value in (("access_token", access), ("refresh_token", refresh), ("csrf_token", "test-csrf")):
            client.cookies.set(name, value, domain="testserver.local")
    return body


def _owner(db):
    from app import models
    return db.query(models.User).filter(models.User.email == OWNER_EMAIL).first() or make_user(db)


def admin_login(client, keep_cookies=False):
    """Sign in as the company owner (owner@x.com); returns {access_token, user}."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        owner_id = _owner(db).id
    finally:
        db.close()
    return login_as(client, owner_id, keep_cookies=keep_cookies)


def admin_headers(client):
    return {"Authorization": f"Bearer {admin_login(client)['access_token']}"}


def admin_tenant(db):
    return _owner(db).tenant
