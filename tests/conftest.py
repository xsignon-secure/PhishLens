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
