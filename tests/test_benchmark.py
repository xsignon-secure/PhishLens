"""Public State of email security page: aggregates only, small groups hidden."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import benchmark, models
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    benchmark._cache.clear()
    s = SessionLocal()
    yield s
    s.close()
    benchmark._cache.clear()


def _scan(db, domain, policy="reject", grade="A", score=95, when=None, errored=False):
    checks = [{"key": "spf", "status": "pass"}, {"key": "dkim", "status": "pass"},
              {"key": "mta-sts", "status": "fail"}]
    if policy:
        checks.append({"key": "dmarc", "status": "pass" if policy == "reject" else "warn",
                       "record": f"v=DMARC1; p={policy}; rua=mailto:x@y.z"})
    else:
        checks.append({"key": "dmarc", "status": "fail"})
    if errored:
        checks.append({"key": "bimi", "status": "warn", "errored": True})
    db.add(models.Scan(domain=domain, score=score, grade=grade, result={"checks": checks},
                       created_at=when or datetime.utcnow()))


def test_not_enough_data_hides_numbers(db):
    for i in range(10):
        _scan(db, f"d{i}.com")
    db.commit()
    data = benchmark.compute(db)
    assert data["enough_data"] is False and "adoption" not in data["overall"] and data["by_tld"] == []
    page = TestClient(app).get("/benchmark")
    assert page.status_code == 200 and "Not enough recent scans" in page.text and "d1.com" not in page.text


def test_aggregates_latest_scan_per_domain(db):
    old = datetime.utcnow() - timedelta(days=5)
    for i in range(40):
        _scan(db, f"a{i}.com", policy="none", grade="F", score=40, when=old)  # superseded below
        _scan(db, f"a{i}.com", policy="reject")
    for i in range(20):
        _scan(db, f"b{i}.de", policy=None, grade="D", score=60)
    for i in range(5):
        _scan(db, f"c{i}.fr", policy="quarantine", grade="B", score=85)
    _scan(db, "gone.com", when=datetime.utcnow() - timedelta(days=200))  # outside window
    _scan(db, "broken.com", errored=True)  # incomplete scan is skipped
    db.commit()
    data = benchmark.compute(db)
    o = data["overall"]
    assert data["enough_data"] and o["domains"] == 65
    assert o["adoption"]["dmarc"] == round(100 * 45 / 65) and o["adoption"]["reject"] == round(100 * 40 / 65)
    assert o["adoption"]["enforced"] == round(100 * 45 / 65) and o["adoption"]["mta_sts"] == 0
    assert [r["tld"] for r in data["by_tld"]] == ["com", "de"]  # .fr has only 5 domains
    body = TestClient(app).get("/benchmark").text
    assert "a1.com" not in body and ".de" in body and ".fr" not in body.split("By top-level domain")[-1].split("</table>")[0]
    assert TestClient(app).get("/api/benchmark").json()["overall"]["domains"] == 65
