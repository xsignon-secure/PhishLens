"""DANE / PTR / IPv6 / RPKI checks, DMARC RFC 9989, DNS providers, leases,
database rate limits."""
import json

import dns.resolver
import httpx
import pytest
from fastapi import HTTPException

from app import dns_providers, models, scheduler
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.scanner import dns_checks, mail_checks
from tests.conftest import admin_headers


class _Rec:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __str__(self):
        return self.__dict__.get("text", "")


@pytest.fixture()
def fake_dns(monkeypatch):
    zone = {}

    def resolve(name, rtype, lifetime=None):
        key = (str(name).rstrip(".").lower(), rtype)
        if key not in zone:
            raise dns.resolver.NoAnswer()
        return zone[key]
    monkeypatch.setattr(dns_checks._resolver, "resolve", resolve)
    monkeypatch.setattr(dns.resolver, "zone_for_name",
                        lambda name, resolver=None, lifetime=None: dns.name.from_text(".".join(str(name).split(".")[-2:])))
    return zone


def _mx(zone, domain, *hosts):
    zone[(domain, "MX")] = [_Rec(preference=i, exchange=h + ".") for i, h in enumerate(hosts)]


def test_dane_pass_and_missing(fake_dns):
    _mx(fake_dns, "x.com", "mx.x.com")
    r = mail_checks.check_dane("x.com")
    assert r["status"] == "warn" and r["max_score"] == 0 and "TLSA" in r["fixes"][0]
    fake_dns[("_25._tcp.mx.x.com", "TLSA")] = [_Rec(usage=3, selector=1, mtype=1)]
    fake_dns[("x.com", "DS")] = [_Rec(text="ds")]
    assert mail_checks.check_dane("x.com")["status"] == "pass"
    fake_dns[("_25._tcp.mx.x.com", "TLSA")] = [_Rec(usage=1, selector=1, mtype=1)]
    r = mail_checks.check_dane("x.com")
    assert r["status"] == "warn" and "PKIX" in r["issues"][0]


def test_ptr_forward_confirmed(fake_dns):
    _mx(fake_dns, "x.com", "mx.x.com")
    fake_dns[("mx.x.com", "A")] = [_Rec(text="203.0.113.5")]
    fake_dns[("5.113.0.203.in-addr.arpa", "PTR")] = [_Rec(text="mx.x.com.")]
    assert mail_checks.check_ptr("x.com")["status"] == "pass"
    fake_dns[("5.113.0.203.in-addr.arpa", "PTR")] = [_Rec(text="host.isp.net.")]
    r = mail_checks.check_ptr("x.com")
    assert r["status"] == "warn" and "doesn't resolve back" in r["issues"][0]
    del fake_dns[("5.113.0.203.in-addr.arpa", "PTR")]
    assert "no PTR" in mail_checks.check_ptr("x.com")["issues"][0]


def test_ipv6_and_null_mx(fake_dns):
    _mx(fake_dns, "x.com", "mx.x.com")
    r = mail_checks.check_ipv6("x.com")
    assert r["status"] == "warn" and len(r["issues"]) == 2
    fake_dns[("mx.x.com", "AAAA")] = [_Rec(text="2001:db8::1")]
    fake_dns[("x.com", "AAAA")] = [_Rec(text="2001:db8::2")]
    assert mail_checks.check_ipv6("x.com")["status"] == "pass"
    fake_dns[("y.com", "MX")] = [_Rec(preference=0, exchange=".")]
    assert "null MX" in mail_checks.check_dane("y.com")["details"]


def test_rpki_off_by_default_and_reads_ripestat(fake_dns, monkeypatch):
    assert "Not checked" in mail_checks.check_rpki("x.com")["details"]
    monkeypatch.setattr(settings, "RPKI_CHECK", True)
    _mx(fake_dns, "x.com", "mx.x.com")
    fake_dns[("mx.x.com", "A")] = [_Rec(text="203.0.113.5")]
    monkeypatch.setattr(mail_checks, "_rpki_status", lambda ip: ("invalid", "203.0.113.0/24"))
    r = mail_checks.check_rpki("x.com")
    assert r["status"] == "warn" and "invalid" in r["issues"][0]


def _dmarc(fake_dns, record):
    fake_dns[("_dmarc.x.com", "TXT")] = [_Rec(strings=[record.encode()])]
    return dns_checks.check_dmarc("x.com")


def test_dmarc_rfc9989_tags(fake_dns):
    r = _dmarc(fake_dns, "v=DMARC1; p=reject; rua=mailto:d@x.com")
    assert r["score"] == 20 and any("np=reject" in f for f in r["fixes"])
    r = _dmarc(fake_dns, "v=DMARC1; p=reject; t=y; rua=mailto:d@x.com")
    assert r["score"] == 17 and "t=y" in r["details"]
    r = _dmarc(fake_dns, "v=DMARC1; p=reject; pct=50; rua=mailto:d@x.com")
    assert r["score"] == 17 and "RFC 9989" in r["issues"][0] and "t=y" in r["fixes"][0]
    r = _dmarc(fake_dns, "v=DMARC1; p=reject; pct=100; rf=afrf; np=none; rua=mailto:d@x.com")
    text = " ".join(r["issues"])
    assert "pct is obsolete" in text and "rf= is obsolete" in text and "np=none" in text


# ------------------------------------------------------------------ DNS providers
def _do_transport(store):
    def handler(req: httpx.Request):
        path = req.url.path
        if path == "/v2/account":
            return httpx.Response(200, json={"account": {"status": "active"}})
        if path == "/v2/domains/x.com":
            return httpx.Response(200, json={"domain": {"name": "x.com"}})
        if path.startswith("/v2/domains/") and path.count("/") == 3:
            return httpx.Response(404, json={"message": "not found"})
        if path == "/v2/domains/x.com/records" and req.method == "GET":
            return httpx.Response(200, json={"domain_records": list(store.values())})
        if path == "/v2/domains/x.com/records" and req.method == "POST":
            body = json.loads(req.content)
            rid = len(store) + 1
            store[rid] = {"id": rid, "type": body["type"], "name": body["name"], "data": body["data"]}
            return httpx.Response(201, json={"domain_record": store[rid]})
        rid = int(path.rsplit("/", 1)[1])
        if req.method == "PUT":
            store[rid]["data"] = json.loads(req.content)["data"]
        elif req.method == "DELETE":
            store.pop(rid)
            return httpx.Response(204)
        return httpx.Response(200, json={"domain_record": store.get(rid)})
    return httpx.MockTransport(handler)


def test_digitalocean_upsert_keeps_unrelated_txt():
    store = {1: {"id": 1, "type": "TXT", "name": "_dmarc", "data": "google-site-verification=1"}}
    do = dns_providers.client("digitalocean", "t" * 40, _do_transport(store))
    assert do.verify()
    zone, _ = do.zone_for("_dmarc.x.com")
    assert zone == "x.com"
    assert do.upsert(zone, "_dmarc.x.com", "TXT", '"v=DMARC1; p=none"') == "created"
    assert store[2]["name"] == "_dmarc" and store[2]["data"] == "v=DMARC1; p=none"
    assert do.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=none") == "unchanged"
    assert do.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=reject") == "updated"
    assert store[1]["data"] == "google-site-verification=1"


def test_desec_rrset_upsert():
    rrsets = {("_dmarc", "TXT"): ['"google-site-verification=1"']}

    def handler(req: httpx.Request):
        path = req.url.path
        if path in ("/api/v1/domains/", "/api/v1/domains/x.com/"):
            return httpx.Response(200, json={"name": "x.com"})
        if path.startswith("/api/v1/domains/") and path.endswith("/") and path.count("/") == 5:
            return httpx.Response(404, json={"detail": "Not found."})
        if req.method == "PUT" and path == "/api/v1/domains/x.com/rrsets/":
            for rr in json.loads(req.content):
                rrsets[(rr["subname"], rr["type"])] = rr["records"]
            return httpx.Response(200, json=[])
        _, sub, rtype = path.rstrip("/").rsplit("/", 2)
        recs = rrsets.get(("" if sub == "@" else sub, rtype))
        return httpx.Response(200, json={"records": recs}) if recs else httpx.Response(404, json={"detail": "Not found."})
    d = dns_providers.client("desec", "t" * 40, httpx.MockTransport(handler))
    zone, _ = d.zone_for("_dmarc.x.com")
    assert d.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=none") == "created"
    assert rrsets[("_dmarc", "TXT")] == ['"google-site-verification=1"', '"v=DMARC1; p=none"']
    assert d.upsert(zone, "_dmarc.x.com", "TXT", "v=DMARC1; p=reject") == "updated"
    assert rrsets[("_dmarc", "TXT")][1] == '"v=DMARC1; p=reject"'


# ------------------------------------------------------------------ leases / rate limits
@pytest.fixture()
def fresh_db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    yield


def test_scheduler_lease_is_exclusive(fresh_db):
    assert scheduler.acquire_lease("rescan", 600, holder="a")
    assert not scheduler.acquire_lease("rescan", 600, holder="b")
    assert scheduler.acquire_lease("rescan", 600, holder="a")  # renew
    db = SessionLocal()
    db.get(models.JobLease, "rescan").expires_at = db.get(models.JobLease, "rescan").expires_at.replace(year=2000)
    db.commit()
    db.close()
    assert scheduler.acquire_lease("rescan", 600, holder="b")


def test_database_rate_limit(fresh_db, monkeypatch):
    from app import deps
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE", "database")
    for _ in range(3):
        deps.rate_limit(None, "k", 3)
    with pytest.raises(HTTPException) as exc:
        deps.rate_limit(None, "k", 3)
    assert exc.value.status_code == 429
    deps.rate_limit(None, "other", 3)


# ------------------------------------------------------------------ API-level: TLS-RPT, tools, metrics
import base64  # noqa: E402
import gzip  # noqa: E402
from email.message import EmailMessage  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app import ip_enrich, tls_reports  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client(fresh_db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.routers.tools.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [{
        "key": "dmarc", "title": "DMARC", "status": "pass", "score": 20, "max_score": 20,
        "details": "stubbed", "issues": [], "fixes": []}])
    return TestClient(app)


def _auth(client, *_args, **_kw):
    return admin_headers(client)


def _tlsrpt(domain="x.com", rid="r1", ok=990, bad=10):
    return json.dumps({
        "organization-name": "Google Inc.", "report-id": rid,
        "date-range": {"start-datetime": "2026-10-20T00:00:00Z", "end-datetime": "2026-10-20T23:59:59Z"},
        "policies": [{"policy": {"policy-type": "sts", "policy-domain": domain, "mx-host": ["mx.x.com"]},
                      "summary": {"total-successful-session-count": ok, "total-failure-session-count": bad},
                      "failure-details": [{"result-type": "certificate-expired", "sending-mta-ip": "203.0.113.9",
                                           "receiving-mx-hostname": "mx.x.com", "failed-session-count": bad}]}]}).encode()


def test_tlsrpt_upload_summary_and_dedupe(client):
    h = _auth(client, "tls@x.com")
    r = client.post("/api/tlsrpt/reports", content=gzip.compress(_tlsrpt()), headers=h)
    assert r.status_code == 201 and r.json()["failed"] == 10
    assert client.post("/api/tlsrpt/reports", content=_tlsrpt(), headers=h).json()["duplicate"] is True
    assert client.post("/api/tlsrpt/reports", content=b"<xml/>", headers=h).status_code == 400
    s = client.get("/api/tlsrpt/summary/x.com?days=3650", headers=h).json()
    assert s["success_rate"] == 99.0 and s["failures"][0]["result_type"] == "certificate-expired"
    assert "renew" in s["failures"][0]["fix"]
    assert client.get("/api/tlsrpt/domains", headers=h).json() == ["x.com"]


def test_tlsrpt_rejects_multi_domain_reports():
    doc = json.loads(_tlsrpt())
    doc["policies"].append({**doc["policies"][0], "policy": {"policy-type": "sts", "policy-domain": "y.com"}})
    with pytest.raises(tls_reports.TlsReportError):
        tls_reports.parse(json.dumps(doc).encode())


def test_mailbox_files_tlsrpt_reports(client):
    from scripts import fetch_dmarc_reports as fetch
    h = _auth(client, "mb@x.com")
    assert client.post("/api/monitors", json={"domain": "x.com"}, headers=h).status_code == 201
    msg = EmailMessage()
    msg["Subject"] = "Report Domain: x.com"
    msg.set_content("TLS report attached")
    msg.add_attachment(gzip.compress(_tlsrpt()), maintype="application", subtype="tlsrpt+gzip",
                       filename="google.com!x.com!1!2!001.json.gz")
    db = SessionLocal()
    assert fetch.file_message(db, msg.as_bytes()) == (1, 0)
    assert db.query(models.TlsReport).count() == 1
    db.close()


def test_graph_and_gmail_sources(monkeypatch):
    from scripts import fetch_dmarc_reports as fetch
    raw = b"Subject: report\r\n\r\nbody"
    calls = []

    def graph(req: httpx.Request):
        calls.append((req.method, req.url.path))
        if "oauth2" in req.url.path:
            return httpx.Response(200, json={"access_token": "t"})
        if req.url.path.endswith("/messages") and req.method == "GET":
            return httpx.Response(200, json={"value": [{"id": "m1"}]})
        if req.url.path.endswith("/$value"):
            return httpx.Response(200, content=raw)
        return httpx.Response(200, json={})
    for k, v in {"DMARC_GRAPH_TENANT_ID": "t", "DMARC_GRAPH_CLIENT_ID": "c", "DMARC_GRAPH_CLIENT_SECRET": "s",
                 "DMARC_GRAPH_MAILBOX": "dmarc@x.com"}.items():
        monkeypatch.setenv(k, v)
    assert list(fetch.graph_messages(httpx.Client(transport=httpx.MockTransport(graph)))) == [raw]
    assert ("PATCH", "/v1.0/users/dmarc@x.com/messages/m1") in calls
    assert fetch.configured_source() is fetch.graph_messages

    def gmail(req: httpx.Request):
        if req.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "t"})
        if req.url.path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": "g1"}]})
        if req.url.path.endswith("/g1"):
            return httpx.Response(200, json={"raw": base64.urlsafe_b64encode(raw).decode().rstrip("=")})
        return httpx.Response(200, json={})
    for k, v in {"DMARC_GMAIL_CLIENT_ID": "c", "DMARC_GMAIL_CLIENT_SECRET": "s",
                 "DMARC_GMAIL_REFRESH_TOKEN": "r"}.items():
        monkeypatch.setenv(k, v)
    assert list(fetch.gmail_messages(httpx.Client(transport=httpx.MockTransport(gmail)))) == [raw]


def test_enrich_summary_names_unknown_senders(monkeypatch):
    monkeypatch.setattr(ip_enrich, "_ptr", lambda ip: "smtp7.mailer.example.net")
    ip_enrich._cache.clear()
    s = ip_enrich.enrich_summary({"senders": [{"sender": "Unknown sender", "sample_ips": ["203.0.113.7"]}]})
    row = s["senders"][0]
    assert row["sources"][0]["ptr"] == "smtp7.mailer.example.net"
    assert row["hint"] == "Reverse DNS: example.net"


def test_public_single_check_and_propagation(client, monkeypatch):
    from app.routers import tools
    monkeypatch.setitem(tools.SINGLE_CHECKS, "spf", lambda d: {"key": "spf", "title": "SPF", "status": "pass",
                                                               "score": 15, "max_score": 15, "details": d,
                                                               "issues": [], "fixes": []})
    assert client.post("/api/tools/check", json={"domain": "x.com", "check": "spf"}).json()["details"] == "x.com"
    assert client.post("/api/tools/check", json={"domain": "x.com", "check": "nope"}).status_code == 404
    monkeypatch.setattr(tools, "_authoritative", lambda name: {"ns1.x.com (authoritative)": "198.51.100.1"})
    monkeypatch.setattr(tools, "_ask", lambda ip, name, t: ["v=DMARC1; p=reject"] if ip != "9.9.9.9" else [])
    r = client.post("/api/tools/propagation", json={"name": "_dmarc.x.com", "type": "TXT"}).json()
    assert r["consistent"] is False and len(r["results"]) == 7
    assert client.post("/api/tools/propagation", json={"name": "bad name", "type": "TXT"}).status_code == 400
    assert client.get("/tools").status_code == 200


def test_metrics_endpoint(client):
    h = _auth(client, "m@x.com")
    client.post("/api/monitors", json={"domain": "x.com", "client": 'Acme "EU"'}, headers=h)
    client.post("/api/tlsrpt/reports", content=_tlsrpt(), headers=h)
    text = client.get("/api/metrics", headers=h).text
    assert 'phishlens_monitor_score{domain="x.com",client="Acme \\"EU\\""} 100' in text
    assert "# TYPE phishlens_dmarc_pass_ratio_30d gauge" in text
    assert client.get("/api/metrics").status_code == 401


# ------------------------------------------------------------------ BIMI
def test_bimi_svg_and_certificate_checks(fake_dns, monkeypatch):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    good_svg = b'<svg version="1.2" baseProfile="tiny-ps" xmlns="http://www.w3.org/2000/svg"><title>X</title></svg>'
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x.com")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2030, 1, 1))
            .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(dns_checks.BIMI_EKU)]), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("x.com")]), False)
            .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(dns_checks.LOGOTYPE_EXT), b"\x30\x00"), False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    files = {"https://x.com/logo.svg": good_svg, "https://x.com/vmc.pem": pem,
             "https://x.com/bad.svg": b"<svg><script>alert(1)</script></svg>"}
    monkeypatch.setattr(dns_checks.net, "safe_fetch_head", lambda url, timeout, limit=4096: (200, files[url][:limit]))
    fake_dns[("default._bimi.x.com", "TXT")] = [_Rec(strings=[b"v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem"])]
    r = dns_checks.check_bimi("x.com")
    assert r["status"] == "pass", r
    fake_dns[("default._bimi.x.com", "TXT")] = [_Rec(strings=[b"v=BIMI1; l=https://x.com/bad.svg"])]
    r = dns_checks.check_bimi("x.com")
    text = " ".join(r["issues"])
    assert "tiny-ps" in text and "<script>" in text and "VMC or CMC" in text and r["score"] == 2


def test_static_assets_are_versioned(client):
    # A cached app.js from an older deploy breaks the new pages' inline scripts,
    # so asset URLs carry a content hash that changes when the files change.
    import re
    html = client.get("/tools").text
    js = re.search(r'/static/app\.js\?v=([0-9a-f]{10})"', html)
    css = re.search(r'/static/style\.css\?v=([0-9a-f]{10})"', html)
    assert js and css and js.group(1) == css.group(1)
    assert client.get(f"/static/app.js?v={js.group(1)}").status_code == 200
