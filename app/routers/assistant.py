"""AI assistant endpoints: chat, and the company's own API key."""
import anthropic
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import assistant, audit, crypto, models
from ..database import get_db
from ..deps import get_current_user, rate_limit, require_step_up
from .mcp import _call

router = APIRouter(tags=["assistant"])


@router.get("/api/assistant")
def assistant_status(user: models.User = Depends(get_current_user)):
    return {"enabled": bool(assistant.api_key(user.tenant)), "own_key": bool(user.tenant.ai_key)}


class Turn(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=8000)


class ChatIn(BaseModel):
    messages: list[Turn] = Field(min_length=1, max_length=30)


@router.post("/api/assistant/chat")
def assistant_chat(body: ChatIn, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    key = assistant.api_key(user.tenant)
    if not key:
        raise HTTPException(status_code=503, detail="The assistant is off: add an Anthropic API key under "
                                                    "Integrations → AI assistant")
    if body.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="The last message must be yours")
    rate_limit(request, f"assistant:{user.id}", 60)
    history = [m.model_dump() for m in body.messages]
    try:
        out = assistant.chat(assistant.client_for(key), history,
                             lambda name, args: _call(name, args, request, db, user))
    except anthropic.AuthenticationError:
        raise HTTPException(status_code=502, detail="The Anthropic API key was refused: check it")
    except anthropic.RateLimitError:
        raise HTTPException(status_code=429, detail="The AI provider is rate limiting this key: try again shortly")
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"The AI provider failed: {getattr(exc, 'message', exc)}")
    audit.log_request(db, request, "assistant.chat", user, {"tools": out["tools_used"]})
    return out


class KeyIn(BaseModel):
    key: str = Field(min_length=20, max_length=300, pattern=r"^sk-ant-[A-Za-z0-9_\-]+$")


@router.put("/api/team/assistant-key")
def set_key(body: KeyIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(require_step_up)):
    user.tenant.ai_key = crypto.encrypt(body.key)
    db.commit()
    audit.log_request(db, request, "assistant.key_set", user, {})
    return {"enabled": True, "own_key": True}


@router.delete("/api/team/assistant-key")
def delete_key(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_step_up)):
    user.tenant.ai_key = None
    db.commit()
    audit.log_request(db, request, "assistant.key_removed", user, {})
    return {"enabled": bool(assistant.api_key(user.tenant)), "own_key": False}
