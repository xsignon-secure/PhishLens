"""Live scan stream for the landing page radar: one event per check as it
finishes, then the same report as POST /api/scans/public, and no fixes."""
import json

from fastapi.testclient import TestClient

from app.main import app
from app.scanner import scoring
from tests.test_fix_guide_gating import FIX, _checks, _no_solutions, client, db  # noqa: F401  (fixtures)


def _events(resp):
    return [json.loads(line) for line in resp.text.splitlines() if line.strip()]


def test_stream_sends_each_check_then_the_report(client, monkeypatch):
    def fake(domain, on_check=None):
        out = _checks(domain)
        for r in out:
            on_check and on_check(r)
        return out
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", fake)
    r = client.post("/api/scans/public/stream", json={"domain": "acme.com"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    ev = _events(r)
    assert ev[0] == {"type": "start", "domain": "acme.com", "total": scoring.check_count()}
    checks = [e for e in ev if e["type"] == "check"]
    assert [(c["key"], c["status"], c["n"]) for c in checks] == [("dmarc", "fail", 1), ("spf", "pass", 2)]
    assert set(checks[0]) == {"type", "key", "title", "status", "n"}  # names and status only
    assert ev[-1]["type"] == "done" and ev[-1]["report"]["domain"] == "acme.com"
    _no_solutions(ev)
    assert FIX not in r.text


def test_stream_rejects_bad_domain_before_streaming(client):
    r = client.post("/api/scans/public/stream", json={"domain": "not a domain"})
    assert r.status_code in (400, 422)


def test_run_all_checks_reports_progress_in_registry_order(monkeypatch):
    calls = []
    a = lambda d: {"key": "a", "status": "pass"}  # noqa: E731
    b = lambda d: {"key": "b", "status": "fail"}  # noqa: E731
    monkeypatch.setattr(scoring, "EMAIL_CHECKS", [a, b])
    monkeypatch.setattr(scoring, "WEB_CHECKS", [])
    out = scoring.run_all_checks("x.example", on_check=lambda r: calls.append(r["key"]))
    assert [r["key"] for r in out] == ["a", "b"] and sorted(calls) == ["a", "b"]
    # A broken progress callback never breaks the scan.
    assert len(scoring.run_all_checks("x.example", on_check=lambda r: 1 / 0)) == 2
