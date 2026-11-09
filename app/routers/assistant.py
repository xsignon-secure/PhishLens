"""AI assistant endpoints: chat, and the company's own AI provider and key."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import ai_providers, assistant, audit, crypto, models
from ..database import get_db
from ..deps import get_current_user, rate_limit, require_step_up
from .mcp import _call

router = APIRouter(tags=["assistant"])


def _status(tenant) -> dict:
    cfg = assistant.config(tenant)
    own = bool(cfg and cfg["own"])
    return {"enabled": bool(cfg), "own_key": own,
            "provider": tenant.ai_provider if own else None,
            "model": cfg["model"] if own else None,
            "base_url": tenant.ai_base_url if own else None,
            "providers": ai_providers.catalog(),
            "private_endpoints": ai_providers.private_endpoints_allowed()}


@router.get("/api/assistant")
def assistant_status(user: models.User = Depends(get_current_user)):
    return _status(user.tenant)


class Turn(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=8000)


class ChatIn(BaseModel):
    messages: list[Turn] = Field(min_length=1, max_length=30)


@router.post("/api/assistant/chat")
def assistant_chat(body: ChatIn, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    cfg = assistant.config(user.tenant)
    if not cfg:
        raise HTTPException(status_code=503, detail="The assistant is off: an owner or admin can choose an AI "
                                                    "provider and add its API key under Assistant")
    if body.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="The last message must be yours")
    rate_limit(request, f"assistant:{user.id}", 60)
    history = [m.model_dump() for m in body.messages]
    try:
        out = assistant.run(cfg, history, lambda name, args: _call(name, args, request, db, user))
    except assistant.AssistantError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    audit.log_request(db, request, "assistant.chat", user, {"tools": out["tools_used"], "provider": cfg["provider"]})
    return out


class KeyIn(BaseModel):
    provider: str = Field(default="anthropic", max_length=30)
    # Empty keeps the saved key (to change only the model or endpoint).
    key: str = Field(default="", max_length=500, pattern=r"^[\x21-\x7e]*$")
    model: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._:/@+\- ]*$")
    base_url: str | None = Field(default=None, max_length=500)


@router.put("/api/team/assistant-key")
def set_key(body: KeyIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(require_step_up)):
    p = ai_providers.PROVIDERS.get(body.provider)
    if not p:
        raise HTTPException(status_code=422, detail="Unknown AI provider")
    tenant = user.tenant
    same_provider = tenant.ai_provider == body.provider
    key = body.key.strip()
    if key and len(key) < 8:
        raise HTTPException(status_code=422, detail="That API key looks too short")
    if body.provider == "anthropic" and key and not key.startswith("sk-ant-"):
        raise HTTPException(status_code=422, detail="Anthropic API keys start with sk-ant-")
    if not key and not (same_provider and tenant.ai_key) and not p.get("key_optional"):
        raise HTTPException(status_code=422, detail="Paste the API key")
    base_url = None
    if p.get("needs_base_url"):
        try:
            base_url = ai_providers.check_base_url(body.base_url or "")
        except ai_providers.ProviderError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    model = (body.model or "").strip() or p["model"]
    if not model:
        raise HTTPException(status_code=422, detail="Enter the model name")
    if key:
        tenant.ai_key = crypto.encrypt(key)
    elif not same_provider:
        tenant.ai_key = None  # never send one provider's key to another
    tenant.ai_provider, tenant.ai_model, tenant.ai_base_url = body.provider, model, base_url
    db.commit()
    audit.log_request(db, request, "assistant.key_set", user, {"provider": body.provider, "model": model})
    return _status(tenant)


@router.delete("/api/team/assistant-key")
def delete_key(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_step_up)):
    t = user.tenant
    t.ai_key = t.ai_provider = t.ai_model = t.ai_base_url = None
    db.commit()
    audit.log_request(db, request, "assistant.key_removed", user, {})
    return _status(t)
