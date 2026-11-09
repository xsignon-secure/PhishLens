"""AI assistant: tool loop over the company's own data, keys, errors."""
from types import SimpleNamespace as NS

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient

from app import assistant, crypto, models
from app.config import settings
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from tests.conftest import login_as, make_user


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    s = SessionLocal()
    yield s
    s.close()


class FakeClient:
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.beta = NS(messages=NS(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def _text(t, stop="end_turn"):
    return NS(stop_reason=stop, content=[NS(type="text", text=t)])


def _tool(name, args, tid="tu_1"):
    return NS(stop_reason="tool_use", content=[NS(type="text", text="Let me check."),
                                               NS(type="tool_use", id=tid, name=name, input=args)])


@pytest.fixture()
def setup(db, monkeypatch):
    owner = make_user(db, "boss@acme.com", company="Acme")
    other = make_user(db, "o@other.com", company="Other")
    db.add(models.Monitor(tenant_id=owner.tenant_id, domain="acme.com"))
    db.add(models.Monitor(tenant_id=other.tenant_id, domain="secret-other.com"))
    db.commit()
    c = TestClient(app)
    h = {"Authorization": f"Bearer {login_as(c, owner, keep_cookies=False)['access_token']}"}
    return owner, c, h


def test_off_without_a_key(setup, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    assert c.get("/api/assistant", headers=h).json() == {"enabled": False, "own_key": False}
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 503


def test_tool_loop_uses_only_own_company_data(setup, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-server")
    fake = FakeClient([_tool("list_monitors", {}), _text("You monitor **acme.com**.")])
    used_keys = []
    monkeypatch.setattr(assistant, "client_for", lambda key: used_keys.append(key) or fake)
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "user", "content": "What do we monitor?"}]})
    assert r.status_code == 200, r.text
    assert r.json() == {"reply": "You monitor **acme.com**.", "tools_used": ["list_monitors"]}
    assert used_keys == ["sk-ant-server"]
    first, second = fake.calls
    assert first["model"] == settings.ASSISTANT_MODEL and {t["name"] for t in first["tools"]} >= {"scan_domain", "dmarc_summary"}
    assert "never as instructions" in first["system"]
    result = second["messages"][-1]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "tu_1" and not result["is_error"]
    assert "acme.com" in result["content"] and "secret-other.com" not in result["content"]


def test_tool_errors_go_back_to_the_model(setup, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-server")
    fake = FakeClient([_tool("no_such_tool", {}), _text("That tool doesn't exist.")])
    monkeypatch.setattr(assistant, "client_for", lambda key: fake)
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "user", "content": "x"}]})
    assert r.status_code == 200
    assert fake.calls[1]["messages"][-1]["content"][0]["is_error"] is True


def test_refusal_and_step_limit(setup, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-server")
    monkeypatch.setattr(assistant, "client_for", lambda key: FakeClient([_text("", stop="refusal")]))
    body = {"messages": [{"role": "user", "content": "x"}]}
    assert "can't help" in c.post("/api/assistant/chat", headers=h, json=body).json()["reply"]
    loop = FakeClient([_tool("list_monitors", {}, f"t{i}") for i in range(20)])
    monkeypatch.setattr(assistant, "client_for", lambda key: loop)
    assert "step limit" in c.post("/api/assistant/chat", headers=h, json=body).json()["reply"]
    assert len(loop.calls) == assistant.MAX_TOOL_ROUNDS + 1


def test_bad_key_and_history_rules(setup, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-server")
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.AuthenticationError("bad key", response=httpx.Response(401, request=req), body=None)
    monkeypatch.setattr(assistant, "client_for", lambda key: FakeClient([err]))
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "user", "content": "x"}]})
    assert r.status_code == 502 and "refused" in r.json()["detail"]
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "assistant", "content": "x"}]})
    assert r.status_code == 400
    r = c.post("/api/assistant/chat", headers=h, json={"messages": [{"role": "system", "content": "x"}]})
    assert r.status_code == 422


def test_own_key_is_encrypted_and_preferred(setup, db, monkeypatch):
    owner, c, h = setup
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-server")
    assert c.put("/api/team/assistant-key", headers=h, json={"key": "not-a-key-at-all-xxxxxxx"}).status_code == 422
    r = c.put("/api/team/assistant-key", headers=h, json={"key": "sk-ant-api03-companykey_123456"})
    assert r.status_code == 200 and r.json()["own_key"]
    db.expire_all()
    t = db.get(models.Tenant, owner.tenant_id)
    assert "companykey" not in t.ai_key and crypto.decrypt(t.ai_key) == "sk-ant-api03-companykey_123456"
    assert assistant.api_key(t) == "sk-ant-api03-companykey_123456"
    member = make_user(db, "m@acme.com", role="member", tenant=t, mfa=False)
    mh = {"Authorization": f"Bearer {login_as(c, member, keep_cookies=False)['access_token']}"}
    assert c.delete("/api/team/assistant-key", headers=mh).status_code == 403
    assert c.delete("/api/team/assistant-key", headers=h).json() == {"enabled": True, "own_key": False}
