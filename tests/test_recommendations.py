"""Product recommendation funnel tests."""
from app.scanner import recommendations


def _check(key, title, status):
    return {"key": key, "title": title, "status": status, "score": 0,
            "max_score": 10, "details": "", "issues": [], "fixes": []}


def test_no_pitch_on_clean_scan():
    checks = [_check("spf", "SPF", "pass"), _check("dmarc", "DMARC", "pass")]
    assert recommendations.build(checks, 96) == []


def test_pitch_when_phishing_gaps_found():
    checks = [_check("spf", "SPF", "fail"), _check("dmarc", "DMARC", "warn"),
              _check("sec-headers", "Web Security Headers", "pass")]
    recs = recommendations.build(checks, 58)
    assert len(recs) == 1
    rec = recs[0]
    assert rec["triggered_by"] == ["SPF", "DMARC"]
    assert "AUTH BioPro" in [p["name"] for p in rec["products"]]
    assert rec["cta"]["href"] == "mailto:info@xsignon.com"
    # no prices anywhere in the funnel copy
    blob = rec["headline"] + rec["body"] + rec["contact"]
    assert "$" not in blob


def test_soft_line_for_non_phishing_gaps():
    checks = [_check("sec-headers", "Web Security Headers", "warn")]
    recs = recommendations.build(checks, 85)
    assert len(recs) == 1
    assert "triggered_by" not in recs[0]


def test_copy_stays_inside_accuracy_bounds():
    checks = [_check("dmarc", "DMARC", "fail")]
    body = recommendations.build(checks, 40)[0]["body"].lower()
    # honest mechanism claims only
    assert "fake login page cannot complete the authentication" in body
    assert "stops replay" not in body
    assert "would have prevented" not in body


def test_attach_adds_to_result():
    result = {"score": 50, "checks": [_check("spf", "SPF", "fail")]}
    out = recommendations.attach(result)
    assert len(out["recommendations"]) == 1


def test_recommendations_survive_db_roundtrip(monkeypatch):
    """Regression: JSON in-place mutation after commit is silently lost by
    SQLAlchemy — recommendations must be in the persisted result."""
    from app import models
    from app.database import Base, SessionLocal, engine as sa_engine
    from app.scanner import engine as scan_engine

    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    db = SessionLocal()
    try:
        monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
        monkeypatch.setattr(
            "app.scanner.scoring.run_all_checks",
            lambda domain: [_check("dmarc", "DMARC", "fail"),
                            _check("spf", "SPF", "pass")],
        )
        scan = scan_engine.run_scan(db, "example.com", tenant_id=None)
        # force expiry like a new request would see
        db.expire(scan)
        d = scan_engine.scan_to_dict(scan)
        assert len(d["result"].get("recommendations", [])) == 1
        # and it is really in the database, not just session memory
        db.expunge_all()
        reloaded = db.query(models.Scan).filter(models.Scan.id == scan.id).first()
        assert len(reloaded.result.get("recommendations", [])) == 1
    finally:
        db.close()
