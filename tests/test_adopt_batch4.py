"""MCP server, "send a test email" analyzer, SIEM export and PSA tickets."""
import json
import socket
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from app import crypto, integrations, mailtest, models
from app.config import settings
from tests.test_fill_gaps import _auth, _tenant, client, db  # noqa: F401  (fixtures)


# ------------------------------------------------------------------ MCP
def _key(client, h):
    return {"Authorization": "Bearer " + client.post("/api/team/keys", json={"name": "mcp"}, headers=h).json()["api_key"]}


def _rpc(client, headers, method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "id": msg_id, "method": method, **({"params": params} if params else {})}
    return client.post("/mcp", json=body, headers=headers)


def test_mcp_handshake_tools_and_auth(client, db):
    h = _auth(client, "o@x.com")
    key = _key(client, h)
    r = _rpc(client, key, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "1"}})
    res = r.json()["result"]
    assert res["protocolVersion"] == "2025-03-26" and "tools" in res["capabilities"]
    assert _rpc(client, key, "initialize", {"protocolVersion": "1999-01-01"}).json()["result"]["protocolVersion"] == "2025-06-18"
    n = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=key)
    assert n.status_code == 202
    names = {t["name"] for t in _rpc(client, key, "tools/list").json()["result"]["tools"]}
    assert names == {"scan_domain", "get_latest_report", "list_monitors", "list_alerts", "dmarc_summary", "dns_changes"}
    assert _rpc(client, key, "nope").json()["error"]["code"] == -32601
    assert _rpc(client, key, "tools/call", {"name": "nope"}).json()["error"]["code"] == -32602

    client.post("/api/monitors", json={"domain": "x.com", "client": "Acme"}, headers=h)
    out = _rpc(client, key, "tools/call", {"name": "list_monitors", "arguments": {}}).json()["result"]
    assert out["isError"] is False and out["structuredContent"]["items"][0]["domain"] == "x.com"
    assert json.loads(out["content"][0]["text"])[0]["client"] == "Acme"
    rep = _rpc(client, key, "tools/call", {"name": "get_latest_report", "arguments": {"domain": "x.com"}}).json()["result"]
    assert rep["structuredContent"]["domain"] == "x.com" and rep["structuredContent"]["problems"][0]["check"] == "DMARC"
    bad = _rpc(client, key, "tools/call", {"name": "get_latest_report", "arguments": {"domain": "not a domain"}}).json()
    assert bad["result"]["isError"] is True
    batch = client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                      {"jsonrpc": "2.0", "method": "notifications/x"}], headers=key).json()
    assert batch == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
    assert client.post("/mcp", content=b"{", headers=key).json()["error"]["code"] == -32700
    assert client.get("/mcp", headers=key).status_code == 405

    # Other teams' data stays out; a browser cookie alone is refused.
    other = _key(client, _auth(client, "p@y.com"))
    got = _rpc(client, other, "tools/call", {"name": "list_monitors", "arguments": {}}).json()["result"]
    assert got["structuredContent"]["items"] == []
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
    client.post("/api/auth/login", json={"email": "o@x.com", "password": "correct-horse-123"})
    assert client.cookies.get("access_token")
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
    assert _rpc(client, {"Authorization": "Bearer plk_wrong"}, "ping").status_code == 401


# ------------------------------------------------------------------ test email
RAW = (b"Delivered-To: check+{token}@reports.example.net\r\n"
       b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=acme.com; "
       b"dkim=pass header.d=acme.com; dmarc=pass header.from=acme.com\r\n"
       b"From: Alice <alice@acme.com>\r\nTo: check+{token}@reports.example.net\r\nSubject: hi\r\n\r\nbody\r\n")


@pytest.fixture()
def mailtest_on(monkeypatch):
    monkeypatch.setattr(settings, "MAILTEST_ADDRESS", "check@reports.example.net")
    monkeypatch.setattr(mailtest, "is_configured", lambda: True)


def test_mailtest_flow(client, db, mailtest_on, monkeypatch):
    from scripts import fetch_dmarc_reports
    h = _auth(client, "o@x.com")
    t = client.post("/api/mailtest", headers=h).json()
    token = t["token"]
    assert t["status"] == "waiting" and t["address"] == f"check+{token}@reports.example.net"
    assert client.get(f"/api/mailtest/{token}", headers=_auth(client, "p@y.com")).status_code == 404

    # The fetch picks it up instead of treating it as a report.
    raw = RAW.replace(b"{token}", token.encode())
    monkeypatch.setattr(fetch_dmarc_reports, "run", lambda: fetch_dmarc_reports.file_message(db, raw))
    got = client.post(f"/api/mailtest/{token}/check", headers=h).json()
    assert got["status"] == "received" and got["result"]["level"] == "pass"
    assert got["result"]["authentication"]["dkim_domain"] == "acme.com"
    # A second copy (or one for an unknown token) is swallowed, not filed as a report.
    assert fetch_dmarc_reports.file_message(db, raw) == (0, 0)
    assert mailtest.record(db, RAW.replace(b"{token}", b"0" * 12)) is True
    assert mailtest.record(db, b"To: someone@else.com\r\n\r\n") is False


def test_mailtest_expiry_and_not_configured(client, db, mailtest_on, monkeypatch):
    h = _auth(client, "o@x.com")
    token = client.post("/api/mailtest", headers=h).json()["token"]
    later = datetime.utcnow() + timedelta(hours=25)
    assert mailtest.record(db, RAW.replace(b"{token}", token.encode()), now=later) is True
    test = db.query(models.MailTest).filter_by(token=token).one()
    assert test.received_at is None and mailtest.as_dict(test, later)["status"] == "expired"
    monkeypatch.setattr(mailtest, "is_configured", lambda: False)
    assert client.post("/api/mailtest", headers=h).status_code == 503
    assert client.get("/api/mailtest/status", headers=h).json() == {"configured": False}


def test_mailtest_address_parsing(monkeypatch):
    monkeypatch.setattr(settings, "MAILTEST_ADDRESS", "Check@Reports.Example.net")
    import email
    msg = email.message_from_string("To: x <check+ABCDEF012345@reports.example.net>\n\n")
    assert mailtest.token_of(msg) == "abcdef012345"
    assert mailtest.token_of(email.message_from_string("To: xcheck+abcdef012345@reports.example.net\n\n")) is None
    monkeypatch.setattr(settings, "MAILTEST_ADDRESS", "a+b@c.com")  # plus already used: refused
    assert mailtest._parts() is None


# ------------------------------------------------------------------ SIEM
def _event(**kw):
    return {"event": "monitor.alert", "domain": "x.com", "client": 'Ac"me', "kind": "score_drop",
            "message": "x.com: score fell\nfrom 90 to 50", "score": 50, "grade": "F",
            "at": "2026-10-28T10:00:00Z", **kw}


def test_syslog_line_is_rfc5424():
    line = integrations.syslog_line(_event()).decode()
    assert line.startswith("<132>1 2026-10-28T10:00:00Z localhost phishlens - score_drop [phishlens@32473 ")
    assert 'client="Ac\\"me"' in line and 'score="50"' in line
    assert line.endswith("] x.com: score fell from 90 to 50")


def test_siem_config_validation(monkeypatch):
    with pytest.raises(integrations.ConfigError, match="public"):
        integrations.clean_siem({"kind": "syslog", "host": "10.1.2.3", "transport": "tcp"})
    with pytest.raises(integrations.ConfigError):
        integrations.clean_siem({"kind": "syslog", "host": "bad host!"})
    with pytest.raises(integrations.ConfigError, match="https"):
        integrations.clean_siem({"kind": "splunk_hec", "url": "http://splunk.example.com", "token": "t"})
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda h: True)
    cfg = integrations.clean_siem({"kind": "splunk_hec", "url": "https://splunk.example.com:8088", "token": "s3cret"})
    assert cfg["url"] == "https://splunk.example.com:8088/services/collector/event"
    assert crypto.decrypt(cfg["token_enc"]) == "s3cret" and "token" not in integrations.public_view(cfg)
    assert integrations.public_view(cfg)["has_token"] is True
    # Blank token keeps the stored one; switching kind needs a new one.
    assert integrations.clean_siem({"kind": "splunk_hec", "url": cfg["url"]}, cfg)["token_enc"] == cfg["token_enc"]
    with pytest.raises(integrations.ConfigError, match="required"):
        integrations.clean_siem({"kind": "splunk_hec", "url": cfg["url"]}, None)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_syslog_delivery(transport):
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    srv = socket.socket(socket.AF_INET, kind)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)  # never leave a thread blocked if delivery goes elsewhere
    port, got = srv.getsockname()[1], []
    if transport == "tcp":
        srv.listen(1)

    def serve():
        if transport == "udp":
            got.append(srv.recvfrom(4096)[0])
        else:
            conn, _ = srv.accept()
            with conn:
                data = b""
                while chunk := conn.recv(4096):
                    data += chunk
                got.append(data)
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    # 127.0.0.1, not localhost: CI runners resolve localhost to ::1 first.
    cfg = integrations.clean_siem({"kind": "syslog", "host": "127.0.0.1", "port": port, "transport": transport})
    assert integrations.send_siem(cfg, [_event()]) is True
    th.join(5)
    srv.close()
    line = integrations.syslog_line(_event())
    assert got[0] == (line if transport == "udp" else str(len(line)).encode() + b" " + line)


def test_hec_delivery_and_kind_filter(monkeypatch):
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda h: True)
    cfg = integrations.clean_siem({"kind": "splunk_hec", "url": "https://hec.example.com/services/collector/event",
                                   "token": "tok", "index": "mail", "kinds": ["dns_changed"]})
    seen = []
    http = httpx.Client(transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200)))
    assert integrations.send_hec(cfg, [_event(), _event(kind="dns_changed")], http) is True
    assert seen[0].headers["authorization"] == "Splunk tok"
    body = [json.loads(x) for x in seen[0].content.decode().replace("}{", "}\n{").splitlines()]
    assert body[0]["index"] == "mail" and body[0]["event"]["domain"] == "x.com" and body[0]["time"] > 0
    assert integrations.send_siem(cfg, [_event()]) is False  # score_drop not selected


# ------------------------------------------------------------------ PSA
def _psa(kind, **extra):
    base = {"connectwise": {"company": "msp", "public_key": "pub", "private_key": "priv", "client_id": "cid",
                            "board": "Security", "default_company": "Catchall"},
            "halopsa": {"url": "https://msp.halopsa.com", "client_id": "cid", "client_secret": "sec",
                        "tenant": "msp", "tickettype_id": 3, "default_company": 12},
            "autotask": {"url": "https://webservices5.autotask.net", "username": "api@msp.com",
                         "integration_code": "CODE", "secret": "sec", "default_company": 0, "queue_id": 9}}[kind]
    return integrations.clean_psa({"kind": kind, **base, **extra})


def test_psa_tickets(monkeypatch):
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda h: True)
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "halo-tok"})
        if "autotask" in req.url.host:
            return httpx.Response(200, json={"itemId": 77})
        if "halopsa" in req.url.host:
            return httpx.Response(201, json={"id": 55})
        return httpx.Response(201, json={"id": 33})
    mock = lambda: httpx.Client(transport=httpx.MockTransport(handler))
    ev = [_event(client="Acme"), _event(client="Acme", kind="dns_changed", message="DMARC changed")]

    cw = _psa("connectwise", companies={"Acme": "ACME01"})
    assert integrations.create_ticket(cw, ev, mock()) == "33"
    r = seen[-1]
    assert r.url == "https://api-na.myconnectwise.net/v4_6_release/apis/3.0/service/tickets"
    assert r.headers["clientid"] == "cid" and r.headers["authorization"].startswith("Basic ")
    import base64
    assert base64.b64decode(r.headers["authorization"][6:]) == b"msp+pub:priv"
    body = json.loads(r.content)
    assert body["company"] == {"identifier": "ACME01"} and body["board"] == {"name": "Security"}
    assert body["summary"] == "PhishLens: x.com email security alert (2)" and "- DMARC changed" in body["initialDescription"]

    assert integrations.create_ticket(_psa("halopsa"), ev, mock()) == "55"
    tok, ticket = seen[-2], seen[-1]
    assert tok.url.params["tenant"] == "msp" and b"client_secret=sec" in tok.content
    assert ticket.headers["authorization"] == "Bearer halo-tok"
    assert json.loads(ticket.content)[0] == {**json.loads(ticket.content)[0], "tickettype_id": 3, "client_id": 12}

    assert integrations.create_ticket(_psa("autotask"), ev, mock()) == "77"
    r = seen[-1]
    assert r.headers["apiintegrationcode"] == "CODE" and r.headers["secret"] == "sec"
    assert json.loads(r.content) == {**json.loads(r.content), "companyID": 0, "queueID": 9, "priority": 2, "status": 1}

    with pytest.raises(integrations.ConfigError, match="https"):
        integrations.clean_psa({"kind": "halopsa", "url": "http://halo.example.com", "client_id": "c", "client_secret": "s"})


def test_integration_api_and_dispatch(client, db, monkeypatch):
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda h: True)
    h = _auth(client, "o@x.com")
    assert client.get("/api/team/integrations", headers=h).json()["siem"] is None
    bad = client.put("/api/team/integrations/siem", json={"kind": "syslog", "host": "10.0.0.1"}, headers=h)
    assert bad.status_code == 400
    r = client.put("/api/team/integrations/psa", json={"kind": "halopsa", "url": "https://msp.halopsa.com",
                                                        "client_id": "c", "client_secret": "s"}, headers=h)
    assert r.status_code == 200 and r.json()["has_client_secret"] is True and "client_secret_enc" not in r.json()
    assert client.get("/api/team/integrations", headers=h).json()["psa"]["url"] == "https://msp.halopsa.com"
    assert client.put("/api/team/integrations/other", json={}, headers=h).status_code == 404

    tickets = []
    monkeypatch.setattr(integrations, "create_ticket", lambda cfg, events, http=None: tickets.append(events) or "9")
    assert client.post("/api/team/integrations/psa/test", headers=h).json() == {"ok": True, "detail": "9"}
    assert tickets[0][0]["kind"] == "test"

    t = _tenant(db, "o@x.com")
    mon = SimpleNamespace(tenant_id=t.id, domain="x.com", client=None)
    scan = SimpleNamespace(score=40, grade="F")
    alert = SimpleNamespace(kind="score_drop", message="m", created_at=datetime.utcnow())
    assert integrations.notify_alerts(db, mon, scan, [alert]) == {"siem": None, "psa": "9"}
    monkeypatch.setattr(integrations, "create_ticket", lambda *a, **k: 1 / 0)
    assert integrations.notify_alerts(db, mon, scan, [alert]) == {"siem": None, "psa": False}
    assert client.delete("/api/team/integrations/psa", headers=h).json() == {"ok": True}
    member = client.get("/api/team/integrations", headers=_auth(client, "p@y.com"))
    assert member.status_code == 200 and member.json()["psa"] is None
