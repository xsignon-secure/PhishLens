"""Admin sign-in. There are no user accounts: one password (ADMIN_PASSWORD)
opens the dashboard."""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, models, security, workspace
from ..config import settings
from ..database import get_db
from ..deps import auth_limit, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    password: str = Field(min_length=1, max_length=500)


def _set_session_cookies(response: Response, token: str) -> None:
    secure = settings.cookie_secure
    response.set_cookie("access_token", token, httponly=True, secure=secure,
                        samesite="lax", max_age=settings.JWT_EXPIRE_MINUTES * 60)
    response.set_cookie("csrf_token", secrets.token_urlsafe(32), secure=secure,
                        samesite="lax", max_age=settings.JWT_EXPIRE_MINUTES * 60)


def _me(user: models.User) -> dict:
    return {"id": user.id, "role": "owner", "tenant_id": user.tenant_id,
            "email": user.email if workspace.real_email(user.email) else None}


@router.post("/login")
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    if not workspace.enabled():
        raise HTTPException(status_code=503, detail="The dashboard is off: set ADMIN_PASSWORD on the server to open it")
    auth_limit(request, "login", "admin")
    admin = workspace.get_admin(db)
    if not workspace.check_password(payload.password):
        audit.log(db, "auth.login_failed", tenant_id=admin.tenant_id,
                  ip=request.client.host if request.client else None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong password")
    audit.log_request(db, request, "auth.login", admin)
    token = security.create_access_token(user_id=admin.id, tenant_id=admin.tenant_id, version=admin.token_version)
    _set_session_cookies(response, token)
    return {"access_token": token, "token_type": "bearer", "user": _me(admin)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        audit.log_request(db, request, "auth.logout", get_current_user(request, None, db))
    except Exception:
        pass
    secure = settings.cookie_secure
    response.delete_cookie("access_token", httponly=True, secure=secure, samesite="lax")
    response.delete_cookie("csrf_token", secure=secure, samesite="lax")
    return {"ok": True}


@router.post("/sessions/revoke")
def revoke_sessions(request: Request, response: Response, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    """Sign out everywhere: every existing session stops working. This browser
    gets a fresh session."""
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    audit.log_request(db, request, "auth.sessions_revoked", user)
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id, version=user.token_version)
    _set_session_cookies(response, token)
    return {"ok": True, "access_token": token}


@router.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return _me(user)
