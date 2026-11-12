"""Plain-language report summary: risk only, never how to fix; AI with a
daily cap, and a fixed-text fallback."""
import pytest
from fastapi.testclient import TestClient

from app import models, summary
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from tests.test_fix_guide_gating import FIX, _checks


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
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "AI_PROVIDER", "")
    return TestClient(app)


def _scan(client):
    return client.post("/api/scans/public", json={"domain": "acme.com"}).json()["id"]


def test_fixed_summary_without_ai_key(client):
    sid = _scan(client)
    d = client.get(f"/api/scans/public/{sid}/summary").json()
    assert d["source"] == "fixed"
    assert "acme.com scored" in d["text"] and "Criminals can currently send email" in d["text"]
    assert not summary.FORBIDDEN.search(d["text"])
    # Stored on the scan, but it's not a fix: the free report still has none.
    report = client.get(f"/api/scans/public/{sid}").json()
    assert report["result"]["summary"]["text"] == d["text"] and FIX not in str(report)


def test_ai_summary_sees_findings_only_and_is_cached(client, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    seen = []

    def fake(cfg, prompt):
        seen.append((cfg, prompt))
        return "Criminals could send fake invoices that look like they come from acme.com. This is urgent."
    monkeypatch.setattr(summary, "_complete", fake)
    sid = _scan(client)
    d = client.get(f"/api/scans/public/{sid}/summary").json()
    assert d == {"text": "Criminals could send fake invoices that look like they come from acme.com. This is urgent.",
                 "source": "ai"}
    cfg, prompt = seen[0]
    assert cfg["model"] == "claude-haiku-5-5" and FIX not in prompt and "DMARC" in prompt
    client.get(f"/api/scans/public/{sid}/summary")
    assert len(seen) == 1  # cached on the scan


@pytest.mark.parametrize("reply", [
    "Add a DMARC record with p=reject to stop spoofing.",
    "Sign in to PhishLens to see the steps.",
    "Your v=DMARC1 policy is missing.",
    "",
])
def test_ai_text_that_hints_at_fixes_falls_back(client, monkeypatch, reply):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(summary, "_complete", lambda cfg, prompt: reply)
    d = client.get(f"/api/scans/public/{_scan(client)}/summary").json()
    assert d["source"] == "fixed"


def test_ai_errors_fall_back(client, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")

    def boom(cfg, prompt):
        raise RuntimeError("provider down")
    monkeypatch.setattr(summary, "_complete", boom)
    assert client.get(f"/api/scans/public/{_scan(client)}/summary").json()["source"] == "fixed"


def test_daily_cap(client, db, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(settings, "PUBLIC_AI_SUMMARY_DAILY_LIMIT", 1)
    calls = []
    monkeypatch.setattr(summary, "_complete", lambda cfg, prompt: calls.append(1) or "Spoofing risk is high.")
    assert client.get(f"/api/scans/public/{_scan(client)}/summary").json()["source"] == "ai"
    assert client.get(f"/api/scans/public/{_scan(client)}/summary").json()["source"] == "fixed"
    assert len(calls) == 1


def test_switch_off(client, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(settings, "PUBLIC_AI_SUMMARY", False)
    monkeypatch.setattr(summary, "_complete", lambda cfg, prompt: pytest.fail("AI must not be called"))
    assert client.get(f"/api/scans/public/{_scan(client)}/summary").json()["source"] == "fixed"


def test_unknown_or_private_scans_404(client):
    assert client.get("/api/scans/public/nope/summary").status_code == 404
    assert client.get("/api/scans/shared/nope/summary").status_code == 404
