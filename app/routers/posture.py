"""Microsoft 365 / Google Workspace security check."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, cloud_posture as cp, models
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, rate_limit, require_admin, require_step_up
from .pages import _user_or_none

router = APIRouter(tags=["cloud security check"])
COOKIE = "posture_state"
CALLBACK = "/posture/m365/callback"


@router.get("/api/posture")
def get_posture(user: models.User = Depends(get_current_user)):
    return cp.summary(user.tenant)


@router.post("/api/posture/run")
def run_now(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    rate_limit(request, f"posture:{user.tenant_id}", 6)
    cp.run(db, user.tenant)
    return cp.summary(user.tenant)


@router.post("/api/posture/m365/connect")
def m365_connect(user: models.User = Depends(require_step_up)):
    try:
        url, cookie = cp.m365_start(user.tenant, user)
    except cp.PostureError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    resp = JSONResponse({"url": url})
    resp.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="lax",
                    max_age=cp.STATE_TTL, path=CALLBACK)
    return resp


@router.get(CALLBACK)
def m365_callback(request: Request, tenant: str = "", state: str = "", admin_consent: str = "",
                  error: str = "", db: Session = Depends(get_db)):
    def done(msg: str) -> RedirectResponse:
        r = RedirectResponse(f"/dashboard?posture={msg}#security", status_code=302)
        r.delete_cookie(COOKIE, path=CALLBACK)
        return r
    user = _user_or_none(request, db)
    if not user or user.role not in ("owner", "admin"):
        return done("signin")
    try:
        data = cp.read_state(request.cookies.get(COOKIE))
    except cp.PostureError:
        return done("expired")
    if data.get("state") != state or data.get("tid") != user.tenant_id or data.get("uid") != user.id:
        return done("expired")
    if error or admin_consent.lower() != "true":
        return done("cancelled")
    try:
        cp.m365_connect(db, user.tenant, tenant)
    except cp.PostureError:
        return done("failed")
    audit.log_request(db, request, "posture.m365_connect", user, {"directory": tenant, "severity": "high"})
    try:
        cp.run(db, user.tenant)
    except Exception:
        db.rollback()
    return done("connected")


class GwsIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    admin_email: str = Field(min_length=3, max_length=254)


@router.put("/api/posture/gws")
def gws_connect(payload: GwsIn, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(require_step_up)):
    if not cp.gws_configured():
        raise HTTPException(status_code=400, detail="The Google Workspace check isn't set up on this server")
    try:
        cp.gws_connect(db, user.tenant, payload.domain, payload.admin_email)
    except cp.PostureError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit.log_request(db, request, "posture.gws_connect", user, {"domain": payload.domain, "severity": "high"})
    cp.run(db, user.tenant)
    return cp.summary(user.tenant)


@router.delete("/api/posture/{kind}", status_code=204)
def disconnect(kind: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    if kind not in ("m365", "gws"):
        raise HTTPException(status_code=404)
    p = dict(user.tenant.posture or {})
    p.pop(kind, None)
    user.tenant.posture = p
    db.commit()
    audit.log_request(db, request, f"posture.{kind}_disconnect", user, {})
    return Response(status_code=204)
