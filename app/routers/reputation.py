"""Sender reputation from Google Postmaster Tools and Microsoft SNDS."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, models, sender_reputation as rep
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, rate_limit, require_admin, require_step_up
from .pages import _user_or_none

router = APIRouter(tags=["sender reputation"])
COOKIE = "postmaster_state"


@router.get("/api/reputation")
def get_reputation(user: models.User = Depends(get_current_user)):
    return rep.summary(user.tenant)


@router.post("/api/reputation/refresh")
def refresh_now(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    rate_limit(request, f"reputation-refresh:{user.tenant_id}", 12)
    rep.refresh(db, user.tenant, force=True)
    return rep.summary(user.tenant)


@router.post("/api/reputation/google/connect")
def google_connect(request: Request, user: models.User = Depends(require_admin)):
    try:
        url, cookie = rep.google_start(user.tenant, user)
    except rep.ReputationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    resp = JSONResponse({"url": url})
    resp.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="lax",
                    max_age=rep.STATE_TTL, path="/reputation/google/callback")
    return resp


@router.get("/reputation/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = "",
                    db: Session = Depends(get_db)):
    def done(msg: str) -> RedirectResponse:
        r = RedirectResponse(f"/dashboard?reputation={msg}#reports", status_code=302)
        r.delete_cookie(COOKIE, path="/reputation/google/callback")
        return r
    user = _user_or_none(request, db)
    if not user or user.role not in ("owner", "admin"):
        return done("signin")
    try:
        data = rep.read_state(request.cookies.get(COOKIE))
    except rep.ReputationError:
        return done("expired")
    if error or not code:
        return done("cancelled")
    if data.get("state") != state or data.get("tid") != user.tenant_id or data.get("uid") != user.id:
        return done("expired")
    try:
        rep.google_finish(db, user.tenant, code, data)
    except rep.ReputationError:
        return done("failed")
    audit.log_request(db, request, "reputation.google_connect", user, {"severity": "high"})
    try:
        rep.refresh(db, user.tenant, force=True)
    except Exception:
        db.rollback()
    return done("connected")


@router.delete("/api/reputation/google", status_code=204)
def google_disconnect(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    rep.google_disconnect(db, user.tenant)
    audit.log_request(db, request, "reputation.google_disconnect", user, {})
    return Response(status_code=204)


class SndsIn(BaseModel):
    key: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9-]*$")


@router.put("/api/reputation/snds")
def set_snds(payload: SndsIn, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_step_up)):
    rep.set_snds_key(db, user.tenant, payload.key)
    audit.log_request(db, request, "reputation.snds_key", user, {"on": bool(payload.key), "severity": "high"})
    if payload.key:
        try:
            rep.refresh(db, user.tenant, force=True)
        except Exception:
            db.rollback()
    return rep.summary(user.tenant)
