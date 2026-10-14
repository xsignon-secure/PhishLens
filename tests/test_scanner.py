"""Scanner engine tests with stubbed DNS (no network)."""
import pytest

from app.scanner import dns_checks, scoring


@pytest.fixture()
def mock_dns(monkeypatch):
    records = {
        "good.com": ["v=spf1 include:_spf.google.com -all"],
        "_dmarc.good.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@good.com"],
        "default._domainkey.good.com": ["v=DKIM1; k=rsa; p=" + "A" * 344],
        "_mta-sts.good.com": ["v=STSv1; id=1"],
        "_smtp._tls.good.com": ["v=TLSRPTv1; rua=mailto:tls@good.com"],
        "default._bimi.good.com": ["v=BIMI1; l=https://good.com/logo.svg"],
    }
    monkeypatch.setattr(dns_checks, "_txt", lambda name: records.get(name, []))


def test_weights_sum_to_100(mock_dns, monkeypatch):
    def _pass(key, title, score, max_score):
        return {"key": key, "title": title, "status": "pass", "score": score,
                "max_score": max_score, "details": "", "issues": [], "fixes": []}
    # Patch the check registries themselves (scoring holds direct references).
    monkeypatch.setattr(scoring, "EMAIL_CHECKS", [
        lambda d: _pass("spf", "SPF", 15, 15),
        lambda d: _pass("dmarc", "DMARC", 20, 20),
        lambda d: _pass("dkim", "DKIM", 15, 15),
        lambda d: _pass("mx", "MX", 5, 5),
        lambda d: _pass("smtp-tls", "SMTP TLS", 5, 5),
        lambda d: _pass("mta-sts", "MTA-STS", 10, 10),
        lambda d: _pass("tls-rpt", "TLS-RPT", 5, 5),
        lambda d: _pass("bimi", "BIMI", 5, 5),
        lambda d: _pass("dnsbl", "Blacklists", 5, 5),
        lambda d: _pass("dnssec", "DNSSEC", 5, 5),
    ])
    monkeypatch.setattr(scoring, "WEB_CHECKS", [
        lambda d: _pass("tls-cert", "TLS Certificate", 5, 5),
        lambda d: _pass("sec-headers", "Web Security Headers", 5, 5),
    ])
    results = scoring.run_all_checks("good.com")
    assert sum(r["max_score"] for r in results) == 100
    score, grade = scoring.score_results(results)
    assert score == 100 and grade == "A"


def test_spf_lookup_limit(mock_dns):
    dns_checks._txt = lambda name: {
        "evil.com": ["v=spf1 " + " ".join(f"include:s{i}.com" for i in range(12)) + " -all"]
    }.get(name, [])
    r = dns_checks.check_spf("evil.com")
    assert r["status"] == "fail"
    assert "12/10 DNS lookups" in r["details"]


def test_spf_plus_all_is_critical(mock_dns):
    dns_checks._txt = lambda name: {"evil.com": ["v=spf1 +all"]}.get(name, [])
    r = dns_checks.check_spf("evil.com")
    assert r["status"] == "fail" and r["score"] == 2


def test_dmarc_none_is_warn(mock_dns):
    dns_checks._txt = lambda name: {"_dmarc.x.com": ["v=DMARC1; p=none"]}.get(name, [])
    r = dns_checks.check_dmarc("x.com")
    assert r["status"] == "warn" and r["score"] <= 5
    assert any("rua" in i for i in r["issues"])


def test_action_plan_orders_by_impact(mock_dns):
    results = scoring.run_all_checks("bad.com")
    plan = scoring.action_plan(results)
    assert plan, "expected fixes for a bare domain"
    points = [p["points"] for p in plan]
    assert points == sorted(points, reverse=True)
    assert plan[0]["check"] == "DMARC"  # 20 recoverable points, highest impact
