"""Certificate Transparency monitoring (crt.sh): unexpected CAs for the
domain, and new certificates on registered lookalike domains."""
import httpx

from app.scanner import ct

ISSUERS = {"le": "C=US, O=Let's Encrypt, CN=R11", "evil": "C=XX, O=Shady CA Ltd, CN=Shady"}


def transport(db):
    """crt.sh fake: db maps a query to [(id, issuer key, names)]."""
    def handler(req):
        q = req.url.params["q"]
        assert req.url.params["output"] == "json"
        rows = [{"id": i, "issuer_name": ISSUERS[iss], "name_value": "\n".join(names),
                 "not_before": "2026-11-01T00:00:00", "not_after": "2027-02-01T00:00:00"}
                for i, iss, names in db.get(q, [])]
        return httpx.Response(200, json=rows)
    return httpx.MockTransport(handler)


def test_baseline_then_alert_on_new_ca_only():
    db = {"%.acme.com": [(1, "le", ["www.acme.com"]), (2, "le", ["mail.acme.com"])],
          "acme.com": [(3, "le", ["acme.com", "www.acme.com"])]}
    state, msgs = ct.check("acme.com", None, None, transport(db))
    assert msgs == [] and state["issuers"] == ["Let's Encrypt"] and state["max_id"] == 3
    # Renewal from the same CA: quiet.
    db["%.acme.com"].append((4, "le", ["www.acme.com"]))
    state, msgs = ct.check("acme.com", state, None, transport(db))
    assert msgs == [] and state["max_id"] == 4
    # A CA never used before: alert.
    db["%.acme.com"].append((5, "evil", ["login.acme.com"]))
    state, msgs = ct.check("acme.com", state, None, transport(db))
    assert len(msgs) == 1 and "Shady CA Ltd" in msgs[0] and "login.acme.com" in msgs[0] and "CAA" in msgs[0]
    # Same certificate again: no repeat.
    assert ct.check("acme.com", state, None, transport(db))[1] == []


def test_lookalike_certificates():
    db = {"acrne.com": [(10, "le", ["acrne.com"])]}
    state, msgs = ct.check("acme.com", None, ["acrne.com"], transport(db))
    assert msgs == [] and state["lookalike_max_id"] == {"acrne.com": 10}
    db["acrne.com"].append((11, "le", ["login.acrne.com"]))
    state, msgs = ct.check("acme.com", state, ["acrne.com"], transport(db))
    assert len(msgs) == 1 and "acrne.com" in msgs[0] and "phishing" in msgs[0]
    # A lookalike first seen later gets a baseline, not an alert.
    db["acme-login.com"] = [(20, "le", ["acme-login.com"])]
    state, msgs = ct.check("acme.com", state, ["acrne.com", "acme-login.com"], transport(db))
    assert msgs == [] and state["lookalike_max_id"]["acme-login.com"] == 20


def test_crt_sh_errors_are_reported_not_raised_wrongly():
    bad = httpx.MockTransport(lambda req: httpx.Response(502, text="busy"))
    try:
        ct.fetch("%.acme.com", bad)
        raise AssertionError("expected CtError")
    except ct.CtError as exc:
        assert "502" in str(exc)


def test_rescan_creates_ct_alerts(monkeypatch):
    from app import models
    from app.database import Base, SessionLocal, engine as sa_engine
    from app.scanner import engine
    from tests.conftest import make_user

    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    db = SessionLocal()
    owner = make_user(db, "boss@acme.com")
    m = models.Monitor(tenant_id=owner.tenant_id, domain="acme.com",
                       ct_state={"issuers": ["Let's Encrypt"], "max_id": 3, "lookalike_max_id": {}})
    db.add(m)
    db.commit()
    data = {"%.acme.com": [(9, "evil", ["vpn.acme.com"])]}
    monkeypatch.setattr(ct, "fetch", lambda q, transport=None: [
        {"id": i, "issuer": "Shady CA Ltd", "names": n} for i, _, n in data.get(q, [])])
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [{
        "key": "spf", "title": "SPF", "status": "pass", "score": 15, "max_score": 15,
        "details": "", "issues": [], "fixes": []}])
    res = engine.rescan_monitor(db, m, check_ct=True)
    assert [a.kind for a in res["alerts"]] == ["ct_certificate"]
    db.refresh(m)
    assert m.ct_state["max_id"] == 9 and "Shady CA Ltd" in m.ct_state["issuers"]
    db.close()
