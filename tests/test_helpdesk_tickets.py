"""Tickets in the open-source helpdesks Zammad and GLPI."""
import json

import httpx
import pytest

from app import integrations
from tests.test_adopt_batch4 import _event


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr("app.scanner.net.is_public_host", lambda h: True)


def test_zammad_ticket():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(201, json={"id": 4, "number": "31004"})
    cfg = integrations.clean_psa({"kind": "zammad", "url": "https://desk.example.com/", "token": "ztok",
                                  "default_company": "IT@Example.com", "companies": {"Acme": "it@acme.com"}})
    assert cfg["group"] == "Users" and cfg["default_company"] == "it@example.com" and "token" not in cfg
    ev = [_event(client="Acme"), _event(client="Acme", kind="dns_changed", message="DMARC changed")]
    assert integrations.create_ticket(cfg, ev, httpx.Client(transport=httpx.MockTransport(handler))) == "31004"
    r = seen[0]
    assert r.url == "https://desk.example.com/api/v1/tickets" and r.headers["authorization"] == "Token token=ztok"
    body = json.loads(r.content)
    assert body["customer_id"] == "guess:it@acme.com" and body["group"] == "Users"
    assert body["article"]["internal"] is False and "- DMARC changed" in body["article"]["body"]

    with pytest.raises(integrations.ConfigError, match="email"):
        integrations.clean_psa({"kind": "zammad", "url": "https://d.example.com", "token": "t", "default_company": "acme"})


def test_glpi_ticket_and_session_closed():
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.path.endswith("/initSession"):
            return httpx.Response(200, json={"session_token": "sess"})
        if req.url.path.endswith("/Ticket"):
            return httpx.Response(201, json={"id": 12, "message": "Item successfully added"})
        return httpx.Response(200, json=[])
    cfg = integrations.clean_psa({"kind": "glpi", "url": "https://glpi.example.com/apirest.php", "user_token": "ut",
                                  "app_token": "at", "default_company": 0, "companies": {"Acme": "3"}})
    assert cfg["url"] == "https://glpi.example.com" and cfg["app_token_enc"] and cfg["user_token_enc"]
    mock = lambda: httpx.Client(transport=httpx.MockTransport(handler))
    assert integrations.create_ticket(cfg, [_event(client="Acme")], mock()) == "12"
    init, ticket, kill = seen
    assert init.headers["authorization"] == "user_token ut" and init.headers["app-token"] == "at"
    assert ticket.headers["session-token"] == "sess" and "authorization" not in ticket.headers
    assert json.loads(ticket.content)["input"] == {**json.loads(ticket.content)["input"], "entities_id": 3, "type": 1}
    assert kill.url.path == "/apirest.php/killSession"

    # Saving again with blank secrets keeps both tokens.
    again = integrations.clean_psa({"kind": "glpi", "url": "https://glpi.example.com"}, cfg)
    assert again["app_token_enc"] == cfg["app_token_enc"] and again["user_token_enc"] == cfg["user_token_enc"]
    # The app token is optional.
    assert "app_token_enc" not in integrations.clean_psa({"kind": "glpi", "url": "https://g.example.com", "user_token": "u"})
    with pytest.raises(integrations.ConfigError, match="numbers"):
        integrations.clean_psa({"kind": "glpi", "url": "https://g.example.com", "user_token": "u", "companies": {"A": "x"}})

    # The session is closed even when the ticket is refused.
    seen.clear()
    refuse = lambda req: (seen.append(req), httpx.Response(400, json=["ERROR"]) if req.url.path.endswith("/Ticket")
                          else httpx.Response(200, json={"session_token": "s"}))[1]
    with pytest.raises(httpx.HTTPStatusError):
        integrations.create_ticket(cfg, [_event()], httpx.Client(transport=httpx.MockTransport(refuse)))
    assert seen[-1].url.path.endswith("/killSession")
