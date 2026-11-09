"""One-click fixes on Hetzner, Porkbun, Vultr, Linode and Gandi, against
in-memory fakes of each API. Every provider must replace only the record of
the same kind and keep unrelated TXT records."""
import itertools
import json

import httpx
import pytest

from app import dns_providers
from app.scanner import guides

ZONE = "acme.com"


def _body(req):
    return json.loads(req.content) if req.content else {}


def hetzner():
    sets = {("@", "TXT"): ['"google-site-verification=abc"', '"v=spf1 -all"']}

    def handler(req):
        p = req.url.path.removeprefix("/v1")
        if p == "/zones":
            name = req.url.params.get("name")
            return httpx.Response(200, json={"zones": [{"id": 7, "name": ZONE}] if name in (None, ZONE) else []})
        parts = p.split("/")  # /zones/7/rrsets/<name>/<type>[/actions/set_records]
        if req.method == "POST" and p == "/zones/7/rrsets":
            b = _body(req)
            sets[(b["name"], b["type"])] = [r["value"] for r in b["records"]]
            return httpx.Response(201, json={})
        key = (parts[4], parts[5])
        if req.method == "GET":
            if key not in sets:
                return httpx.Response(404, json={"error": {"message": "not found"}})
            return httpx.Response(200, json={"rrset": {"records": [{"value": v} for v in sets[key]]}})
        if req.method == "POST":
            sets[key] = [r["value"] for r in _body(req)["records"]]
            return httpx.Response(201, json={})
        if req.method == "DELETE":
            sets.pop(key, None)
            return httpx.Response(201, json={})
    return "hetzner", "x" * 30, handler, lambda: sets.get(("@", "TXT"), []), lambda: sets.get(("_dmarc", "TXT"), [])


def porkbun():
    ids = itertools.count(1)
    recs = {next(ids): {"name": "", "type": "TXT", "content": "google-site-verification=abc"},
            next(ids): {"name": "", "type": "TXT", "content": "v=spf1 -all"}}

    def handler(req):
        b = _body(req)
        if b.get("apikey") != "pk1_key" or b.get("secretapikey") != "sk1_secret":
            return httpx.Response(400, json={"status": "ERROR", "message": "Invalid API key"})
        p = req.url.path.removeprefix("/api/json/v3")
        if p == "/ping":
            return httpx.Response(200, json={"status": "SUCCESS"})
        if p.startswith("/dns/retrieveByNameType/"):
            _, _, _, dom, rtype, *sub = p.split("/")
            sub = sub[0] if sub else ""
            return httpx.Response(200, json={"status": "SUCCESS", "records": [
                {"id": str(i), **r} for i, r in recs.items() if r["type"] == rtype and r["name"] == sub]})
        if p.startswith("/dns/retrieve/"):
            ok = p.endswith("/" + ZONE)
            return httpx.Response(200 if ok else 400, json={"status": "SUCCESS" if ok else "ERROR"})
        if p.startswith("/dns/create/"):
            recs[next(ids)] = {k: b[k] for k in ("name", "type", "content")}
            return httpx.Response(200, json={"status": "SUCCESS"})
        if p.startswith("/dns/edit/"):
            recs[int(p.split("/")[-1])].update({k: b[k] for k in ("name", "type", "content")})
            return httpx.Response(200, json={"status": "SUCCESS"})
        if p.startswith("/dns/delete/"):
            recs.pop(int(p.split("/")[-1]))
            return httpx.Response(200, json={"status": "SUCCESS"})

    def at(name):
        return lambda: [r["content"] for r in recs.values() if r["name"] == name and r["type"] == "TXT"]
    return "porkbun", "pk1_key:sk1_secret", handler, at(""), at("_dmarc")


def vultr():
    ids = itertools.count(1)
    recs = {str(next(ids)): {"name": "", "type": "TXT", "data": '"google-site-verification=abc"'},
            str(next(ids)): {"name": "", "type": "TXT", "data": '"v=spf1 -all"'}}

    def handler(req):
        p = req.url.path.removeprefix("/v2")
        if p == "/account":
            return httpx.Response(200, json={"account": {}})
        if p == f"/domains/{ZONE}":
            return httpx.Response(200, json={"domain": {"domain": ZONE}})
        if p.startswith("/domains/") and p.count("/") == 2:
            return httpx.Response(404, json={"error": "not found"})
        if p == f"/domains/{ZONE}/records":
            if req.method == "GET":
                return httpx.Response(200, json={"records": [{"id": i, **r} for i, r in recs.items()]})
            recs[str(next(ids))] = {k: _body(req)[k] for k in ("name", "type", "data")}
            return httpx.Response(201, json={})
        rid = p.split("/")[-1]
        if req.method == "PATCH":
            recs[rid].update({k: _body(req)[k] for k in ("name", "data")})
        else:
            recs.pop(rid)
        return httpx.Response(204)

    def at(name):
        return lambda: [r["data"].strip('"') for r in recs.values() if r["name"] == name and r["type"] == "TXT"]
    return "vultr", "v" * 30, handler, at(""), at("_dmarc")


def linode():
    ids = itertools.count(1)
    recs = {next(ids): {"name": "", "type": "TXT", "target": "google-site-verification=abc"},
            next(ids): {"name": "", "type": "TXT", "target": "v=spf1 -all"}}

    def handler(req):
        p = req.url.path.removeprefix("/v4")
        if p == "/profile":
            return httpx.Response(200, json={})
        if p == "/domains":
            want = json.loads(req.headers["X-Filter"])["domain"]
            return httpx.Response(200, json={"data": [{"id": 42, "domain": ZONE}] if want == ZONE else []})
        if p == "/domains/42/records":
            if req.method == "GET":
                return httpx.Response(200, json={"data": [{"id": i, **r} for i, r in recs.items()], "pages": 1})
            recs[next(ids)] = {k: _body(req)[k] for k in ("name", "type", "target")}
            return httpx.Response(200, json={})
        rid = int(p.split("/")[-1])
        if req.method == "PUT":
            recs[rid].update({k: _body(req)[k] for k in ("name", "type", "target")})
        else:
            recs.pop(rid)
        return httpx.Response(200, json={})

    def at(name):
        return lambda: [r["target"] for r in recs.values() if r["name"] == name and r["type"] == "TXT"]
    return "linode", "l" * 30, handler, at(""), at("_dmarc")


def gandi():
    sets = {("@", "TXT"): ['"google-site-verification=abc"', '"v=spf1 -all"']}

    def handler(req):
        p = req.url.path.removeprefix("/v5/livedns")
        if p == "/domains":
            return httpx.Response(200, json=[])
        parts = p.split("/")
        if len(parts) == 3:
            return httpx.Response(200 if parts[2] == ZONE else 404, json={})
        key = (parts[4], parts[5])
        if req.method == "GET":
            return httpx.Response(200, json={"rrset_values": sets[key]}) if key in sets else httpx.Response(404, json={})
        if req.method == "PUT":
            sets[key] = _body(req)["rrset_values"]
        else:
            sets.pop(key, None)
        return httpx.Response(201, json={})
    return "gandi", "g" * 30, handler, lambda: sets.get(("@", "TXT"), []), lambda: sets.get(("_dmarc", "TXT"), [])


FAKES = [hetzner, porkbun, vultr, linode, gandi]


@pytest.mark.parametrize("fake", FAKES, ids=lambda f: f.__name__)
def test_provider_upserts_only_matching_record(fake):
    provider, token, handler, apex, dmarc = fake()
    c = dns_providers.client(provider, token, httpx.MockTransport(handler))
    assert c.verify()
    zone_id, zone = c.zone_for("_dmarc.acme.com")
    assert zone == ZONE
    assert c.upsert(zone_id, "acme.com", "TXT", "v=spf1 include:_spf.google.com -all") == "updated"
    vals = [dns_providers._txt_content(v) for v in apex()]
    assert sorted(vals) == ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"]
    assert c.upsert(zone_id, "acme.com", "TXT", "v=spf1 include:_spf.google.com -all") == "unchanged"
    assert c.upsert(zone_id, "_dmarc.acme.com", "TXT", "v=DMARC1; p=none") == "created"
    assert [dns_providers._txt_content(v) for v in dmarc()] == ["v=DMARC1; p=none"]
    assert c.delete_matching(zone_id, "_dmarc.acme.com", "TXT", "v=DMARC1; p=reject") == 1
    assert dmarc() == []
    assert [dns_providers._txt_content(v) for v in apex()][0] == "google-site-verification=abc"


@pytest.mark.parametrize("fake", FAKES, ids=lambda f: f.__name__)
def test_provider_unknown_zone(fake):
    provider, token, handler, *_ = fake()
    c = dns_providers.client(provider, token, httpx.MockTransport(handler))
    with pytest.raises(dns_providers.DnsProviderError):
        c.zone_for("other.org")


def test_long_txt_values_round_trip():
    assert dns_providers._txt_content('"' + "a" * 255 + '" "bbb"') == "a" * 255 + "bbb"
    assert dns_providers._txt_content('"v=spf1 -all"') == "v=spf1 -all"


def test_porkbun_needs_key_and_secret():
    with pytest.raises(dns_providers.DnsProviderError):
        dns_providers.client("porkbun", "just-a-key-without-secret")


def test_nameservers_detect_new_hosts():
    assert guides.match_nameservers(["hydrogen.ns.hetzner.com."])["key"] == "hetzner"
    assert guides.match_nameservers(["curitiba.ns.porkbun.com."])["key"] == "porkbun"
    assert guides.match_nameservers(["ns1.gandi.net."])["key"] == "gandi"
