"""Deep-scanner tests: real crypto parsing, null MX, CAA, advanced signals."""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.scanner import dns_checks


def _b64_pubkey(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return base64.b64encode(der).decode()


def _b64_weak_pubkey(modulus_bytes: int = 64) -> str:
    """Hand-built PKCS#1 DER with a tiny modulus — real libs refuse to generate these."""
    mod = b"\xc1" + b"\x02" * (modulus_bytes - 1)  # top bit set, like a real modulus
    exp = b"\x01\x00\x01"
    def enc_int(b: bytes) -> bytes:
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc_int(mod) + enc_int(exp)
    der = b"\x30" + bytes([len(body)]) + body
    return base64.b64encode(der).decode()


def test_dkim_parses_true_modulus_bits():
    assert dns_checks._dkim_key_bits(_b64_pubkey(2048)) == 2048
    assert dns_checks._dkim_key_bits(_b64_pubkey(1024)) == 1024
    assert dns_checks._dkim_key_bits("not-base64!!") is None
    assert dns_checks._dkim_key_bits("") is None


def test_dkim_weak_key_fails():
    dns_checks._txt = lambda name: {
        "s1._domainkey.x.com": ["v=DKIM1; k=rsa; p=" + _b64_weak_pubkey(64)]
    }.get(name, [])
    r = dns_checks.check_dkim("x.com")
    assert r["status"] == "fail"
    assert "512-bit" in r["details"]


def test_dkim_strong_key_passes():
    dns_checks._txt = lambda name: {
        "default._domainkey.x.com": ["v=DKIM1; k=rsa; p=" + _b64_pubkey(2048)]
    }.get(name, [])
    r = dns_checks.check_dkim("x.com")
    assert r["status"] == "pass" and r["score"] == 15


def test_spf_ptr_mechanism_warns():
    dns_checks._txt = lambda name: {
        "x.com": ["v=spf1 ptr -all"]
    }.get(name, [])
    r = dns_checks.check_spf("x.com")
    assert r["status"] == "warn"
    assert any("ptr" in i for i in r["issues"])


def test_spf_open_cidr_fails():
    dns_checks._txt = lambda name: {
        "x.com": ["v=spf1 ip4:0.0.0.0/0 -all"]
    }.get(name, [])
    r = dns_checks.check_spf("x.com")
    assert r["status"] == "fail" and r["score"] == 2


def test_null_mx_passes(monkeypatch):
    class FakeExchange:
        def __str__(self):
            return "."
    class FakeRec:
        preference = 0
        exchange = FakeExchange()
    monkeypatch.setattr(dns_checks._resolver, "resolve",
                        lambda n, t, lifetime=None: [FakeRec()])
    r = dns_checks.check_mx("x.com")
    assert r["status"] == "pass"
    assert "RFC 7505" in r["details"]


def test_dmarc_weak_subdomain_policy_flagged():
    dns_checks._txt = lambda name: {
        "_dmarc.x.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:d@x.com"]
    }.get(name, [])
    r = dns_checks.check_dmarc("x.com")
    assert r["status"] == "pass"  # org policy still strong
    assert any("sp=none" in i for i in r["issues"])


def test_caa_missing_warns(monkeypatch):
    def boom(*a, **k):
        raise Exception("no records")
    monkeypatch.setattr(dns_checks._resolver, "resolve", boom)
    r = dns_checks.check_caa("x.com")
    assert r["status"] == "warn"
    assert r["max_score"] == 5
    assert "any public CA" in r["details"] or "any CA" in r["details"]


def test_caa_with_issue_tag_passes(monkeypatch):
    class FakeCAA:
        flags = 0
        tag = b"issue"
        value = b"letsencrypt.org"
    monkeypatch.setattr(dns_checks._resolver, "resolve",
                        lambda n, t, lifetime=None: [FakeCAA()])
    r = dns_checks.check_caa("x.com")
    assert r["status"] == "pass" and r["score"] == 5


def test_weights_still_sum_to_100():
    import inspect
    import re
    from app.scanner import scoring
    total = 0
    for fn in scoring.EMAIL_CHECKS + scoring.WEB_CHECKS:
        if fn.__module__.endswith("mail_checks"):  # informational, never scored
            continue
        m = re.search(r"max_score\s*=\s*(\d+)", inspect.getsource(fn))
        assert m, f"no max_score found in {fn.__name__}"
        total += int(m.group(1))
    assert total == 100
