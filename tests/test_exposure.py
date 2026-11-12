"""Dangling DNS (subdomain takeover) and post-quantum readiness checks."""
from types import SimpleNamespace

import dns.resolver
import pytest

from app.config import settings
from app.scanner import dns_checks, exposure, gating, guides, scoring


@pytest.fixture
def zone(monkeypatch):
    """Fake DNS: (name, type) -> records. Names in `nx` don't exist at all."""
    z = {"nx": set()}

    def resolve(name, rtype, lifetime=None):
        name = str(name).rstrip(".").lower()
        if (name, rtype) in z:
            return z[(name, rtype)]
        if name in z["nx"]:
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()
    monkeypatch.setattr(dns_checks._resolver, "resolve", resolve)
    monkeypatch.setattr(exposure, "_body_matches", lambda name, fp: name in z.get("unclaimed", set()))
    return z


def _cname(z, name, target):
    z[(name, "CNAME")] = [SimpleNamespace(target=target + ".")]


def test_clean_domain_passes(zone):
    zone[("x.com", "A")] = ["203.0.113.1"]
    r = exposure.check_dangling("x.com")
    assert r["status"] == "pass" and r["max_score"] == 0


def test_cname_to_deleted_cloud_resource_is_a_takeover(zone):
    _cname(zone, "shop.x.com", "x-old.myshopify.com")
    zone["nx"].add("x-old.myshopify.com")
    r = exposure.check_dangling("x.com")
    assert r["status"] == "fail" and r["max_score"] == 0
    assert "shop.x.com" in r["issues"][0] and "Shopify" in r["issues"][0]
    assert "Delete the CNAME record for shop.x.com" in r["fixes"][0]
    assert r["findings"][0]["severity"] == "high"


def test_unclaimed_service_found_by_page_fingerprint(zone):
    _cname(zone, "docs.x.com", "xco.github.io")
    zone[("xco.github.io", "A")] = ["185.199.108.153"]
    zone["unclaimed"] = {"docs.x.com"}
    r = exposure.check_dangling("x.com")
    assert r["status"] == "fail" and "GitHub Pages" in r["issues"][0]


def test_cname_to_unknown_missing_host_is_only_a_warning(zone):
    _cname(zone, "blog.x.com", "old.vendor-example.net")
    zone["nx"].add("old.vendor-example.net")
    zone[("vendor-example.net", "NS")] = ["ns1"]
    r = exposure.check_dangling("x.com")
    assert r["status"] == "warn"


def test_cname_to_unregistered_domain_is_a_takeover(zone):
    _cname(zone, "promo.x.com", "promo.expired-agency.com")
    zone["nx"] |= {"promo.expired-agency.com", "expired-agency.com"}
    r = exposure.check_dangling("x.com")
    assert r["status"] == "fail" and "nobody has registered" in r["issues"][0]


def test_mx_and_nameserver_on_expired_domains(zone):
    zone[("x.com", "MX")] = [SimpleNamespace(preference=10, exchange="mx.gone-mail.net.")]
    zone[("x.com", "NS")] = [SimpleNamespace(target="ns1.gone-dns.org.")]
    zone["nx"] |= {"mx.gone-mail.net", "gone-mail.net", "ns1.gone-dns.org", "gone-dns.org"}
    r = exposure.check_dangling("x.com")
    assert r["status"] == "fail"
    text = " ".join(r["issues"])
    assert "receive this domain's mail" in text and "answer DNS for this domain" in text


def test_ct_names_widen_the_check(zone):
    _cname(zone, "legacy-portal.x.com", "lp.azurewebsites.net")
    zone["nx"].add("lp.azurewebsites.net")
    assert exposure.check_dangling("x.com")["status"] == "pass"
    r = exposure.check_dangling("x.com", extra_names=["legacy-portal.x.com", "evil.other.com"])
    assert r["status"] == "fail" and r["findings"][0]["name"] == "legacy-portal.x.com"
    assert all(f["name"] != "evil.other.com" for f in r["findings"])


def test_dangling_is_registered_and_free_report_hides_the_fix(zone):
    assert exposure.check_dangling in scoring.EMAIL_CHECKS and exposure.check_pqc in scoring.WEB_CHECKS
    _cname(zone, "shop.x.com", "x-old.myshopify.com")
    zone["nx"].add("x-old.myshopify.com")
    check = exposure.check_dangling("x.com")
    result = {"domain": "x.com", "checks": [check], "action_plan": scoring.action_plan([check])}
    guides.attach(result)
    assert result["checks"][0]["guide"]["steps"]
    free = gating.findings_only(result)
    c = free["checks"][0]
    assert c["issues"] and not c.get("fixes") and "guide" not in c
    assert "Delete" not in str(free)


def test_pqc_reports_each_outcome(monkeypatch):
    monkeypatch.setattr(exposure.net, "is_public_host", lambda h: True)
    monkeypatch.setattr(exposure, "_pqc_handshake", lambda h: "pqc")
    r = exposure.check_pqc("x.com")
    assert r["status"] == "pass" and r["pqc"] is True and r["max_score"] == 0
    monkeypatch.setattr(exposure, "_pqc_handshake", lambda h: "classic")
    r = exposure.check_pqc("x.com")
    assert r["status"] == "warn" and "X25519MLKEM768" in r["fixes"][0]
    monkeypatch.setattr(exposure, "_pqc_handshake", lambda h: None)
    assert "Not checked" in exposure.check_pqc("x.com")["details"]
    monkeypatch.setattr(settings, "PQC_CHECK", False)
    assert "turned off" in exposure.check_pqc("x.com")["details"]


def test_ct_state_records_subdomains():
    from app.scanner import ct
    certs = [{"id": 1, "issuer": "Let's Encrypt", "names": ["*.x.com", "shop.x.com", "x.com", "evil.com"]}]
    import unittest.mock as m
    with m.patch.object(ct, "fetch", side_effect=[certs, []]):
        state, _ = ct.check("x.com", None, [])
    assert state["subdomains"] == ["shop.x.com"]
