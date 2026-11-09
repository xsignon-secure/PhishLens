"""Hosted DKIM: customers CNAME each selector to PhishLens once; key
rotation and revocation then happen here without touching their DNS."""
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app import hosted
from tests.test_fill_gaps import _auth, client, db, hosted_on  # noqa: F401  (fixtures)


def _rsa_p(bits=2048):
    if bits < 1024:  # too weak to generate: build the public key directly
        key = rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 0xFFFF1).public_key()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    return base64.b64encode(key.public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


P2048 = _rsa_p()


def test_dkim_key_validation():
    rec, info = hosted.clean_dkim_key(f'"v=DKIM1; k=rsa; " "p={P2048[:100]}" "{P2048[100:]}"')
    assert rec == f"v=DKIM1; k=rsa; p={P2048}" and info == {"type": "rsa", "bits": 2048}
    assert hosted.clean_dkim_key(P2048)[0] == f"v=DKIM1; k=rsa; p={P2048}"  # bare key
    ed = base64.b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    assert hosted.clean_dkim_key(f"v=DKIM1; k=ed25519; p={ed}")[1]["type"] == "ed25519"
    for bad in ("v=DKIM1; p=", "v=DKIM1; p=not*base64", f"v=DKIM1; k=dsa; p={P2048}",
                f"v=DKIM1; p={_rsa_p(512)}", "v=DKIM1; k=ed25519; p=AAAA"):
        with pytest.raises(hosted.HostedError):
            hosted.clean_dkim_key(bad)
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("dkim", {"keys": [{"selector": "s1", "value": P2048},
                                              {"selector": "S1", "value": P2048}]}, "x.com")
    with pytest.raises(hosted.HostedError):
        hosted.clean_config("dkim", {"keys": [{"selector": "bad selector", "value": P2048}]}, "x.com")


def test_hosted_dkim_publish_rotate_revoke(client, hosted_on):
    h = _auth(client, "o@x.com")
    client.post("/api/scans", json={"domain": "x.com"}, headers=h)
    r = client.put("/api/hosted/x.com/dkim", headers=h,
                   json={"config": {"keys": [{"selector": "s2025._domainkey", "value": P2048}]}})
    assert r.status_code == 200, r.text
    rec = r.json()
    (name, value), = rec["published"].items()
    assert name.startswith("s2025.x.com.") and name.endswith("._dkim.hosted.test")
    assert value == f"v=DKIM1; k=rsa; p={P2048}"
    assert rec["customer_records"] == [{"name": "s2025._domainkey.x.com", "type": "CNAME", "value": name,
                                        "note": "Delete any existing TXT record at this name first."}]
    # Rotate: add a new selector, revoke the old one. Only PhishLens's zone changes.
    new = _rsa_p()
    rec = client.put("/api/hosted/x.com/dkim", headers=h, json={"config": {"keys": [
        {"selector": "s2026", "value": new}, {"selector": "s2025", "revoked": True}]}}).json()
    pub = {n.split(".")[0]: v for n, v in rec["published"].items()}
    assert pub == {"s2026": f"v=DKIM1; k=rsa; p={new}", "s2025": "v=DKIM1; p="}
    live = {r["name"].split(".")[0]: r["content"] for r in hosted_on.values()}
    assert live == pub
    # Dropping a selector removes its record from the hosted zone.
    rec = client.put("/api/hosted/x.com/dkim", headers=h,
                     json={"config": {"keys": [{"selector": "s2026", "value": new}]}}).json()
    assert [r["name"].split(".")[0] for r in hosted_on.values()] == ["s2026"]
