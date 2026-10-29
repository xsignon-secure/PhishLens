"""Sign-in for accounts created by a company admin.

Login answers the same "Invalid email or password" for an unknown email, a
wrong password, a locked or a suspended account, so nobody can find out who
has an account. A correct password then leads to one of three next steps,
each carried by a short step token that opens nothing else:
change_password (first sign-in with the temporary password), mfa (the
authenticator code), or done (a session).
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, models, passwords, security, sessions
from ..database import get_db
from ..deps import auth_limit, get_current_user, rate_limit

router = APIRouter(prefix="/api/auth", tags=["auth"])

GENERIC_FAIL = "Invalid email or password"
LOCK_AFTER = 5
LOCK_MINUTES = 15


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=500)

    model_config = {"extra": "forbid"}


class FirstPasswordIn(BaseModel):
    step_token: str = Field(min_length=10, max_length=2000)
    password: str = Field(min_length=1, max_length=500)

    model_config = {"extra": "forbid"}


class MfaIn(BaseModel):
    step_token: str = Field(min_length=10, max_length=2000)
    code: str = Field(min_length=6, max_length=20)

    model_config = {"extra": "forbid"}


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=20)

    model_config = {"extra": "forbid"}


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=500)
    new_password: str = Field(min_length=1, max_length=500)

    model_config = {"extra": "forbid"}


def me_out(user: models.User) -> dict:
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role,
            "tenant_id": user.tenant_id, "company": user.tenant.name if user.tenant else None,
            "mfa_enabled": bool(user.mfa_enabled),
            "mfa_required": user.role in ("owner", "admin"),
            "recovery_codes_left": len(user.recovery_codes or [])}


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _start_session(db: Session, user: models.User, request: Request, response: Response, *, mfa: bool) -> dict:
    access, refresh, _ = sessions.create(db, user, request, mfa=mfa)
    sessions.set_cookies(response, access, refresh, new_csrf=True)
    audit.log_request(db, request, "auth.login", user, {"mfa": mfa})
    return {"next": "done", "access_token": access, "token_type": "bearer", "user": me_out(user)}


def _after_password(db: Session, user: models.User, request: Request, response: Response) -> dict:
    """What a user who just proved their password does next."""
    if user.mfa_enabled:
        return {"next": "mfa", "step_token": security.create_step_token(user_id=user.id, purpose="mfa")}
    # Owners and admins without an authenticator get a session that can only
    # set one up (see deps.MFA_SETUP_PATHS).
    return _start_session(db, user, request, response, mfa=False)


def _step_user(db: Session, token: str, purpose: str) -> models.User:
    claims = security.decode_token(token, allowed_types=(purpose,))
    user = db.get(models.User, claims["sub"]) if claims else None
    if not user or not sessions.account_usable_or_pending(user):
        raise HTTPException(status_code=401, detail="This step expired. Sign in again")
    return user


@router.post("/login")
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    # 5 tries per account and 15 per address in 15 minutes.
    auth_limit(request, "login", email, limit=LOCK_AFTER, window_secs=LOCK_MINUTES * 60)
    user = db.query(models.User).filter(models.User.email == email).first()
    now = datetime.utcnow()
    ok = passwords.verify(payload.password, user.password_hash if user else None)  # constant work either way
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_FAIL)
    if user.locked_until and user.locked_until > now:
        audit.log(db, "auth.login_locked", user=user, ip=_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_FAIL)
    if not ok:
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= LOCK_AFTER:
            # Lock doubles with each further failure, up to a day.
            minutes = min(LOCK_MINUTES * 2 ** (user.failed_logins - LOCK_AFTER), 24 * 60)
            user.locked_until = now + timedelta(minutes=minutes)
        db.commit()
        audit.log(db, "auth.login_failed", user=user, ip=_ip(request),
                  detail={"failures": user.failed_logins, "locked": bool(user.locked_until and user.locked_until > now)})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_FAIL)
    if not sessions.account_usable_or_pending(user):
        audit.log(db, "auth.login_refused", user=user, ip=_ip(request), detail={"status": user.status})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_FAIL)
    user.failed_logins, user.locked_until = 0, None
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(payload.password)
    db.commit()
    if user.must_change_password:
        if not user.temp_password_expires_at or user.temp_password_expires_at < now:
            audit.log(db, "auth.temp_password_expired", user=user, ip=_ip(request))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Your temporary password has expired. Ask your administrator to send new login details")
        return {"next": "change_password",
                "step_token": security.create_step_token(user_id=user.id, purpose="pwchange")}
    return _after_password(db, user, request, response)


@router.post("/first-password")
def first_password(payload: FirstPasswordIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Replace the temporary password. Nothing else is reachable before this."""
    user = _step_user(db, payload.step_token, "pwchange")
    if not user.must_change_password or not user.temp_password_expires_at \
            or user.temp_password_expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="This step expired. Sign in again")
    if passwords.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Choose a password different from the temporary one")
    try:
        passwords.check_policy(payload.password, email=user.email)
    except passwords.PasswordError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    user.password_hash = passwords.hash_password(payload.password)
    user.must_change_password, user.temp_password_expires_at = False, None
    user.status = "active"
    db.commit()
    audit.log_request(db, request, "auth.first_password", user)
    return _after_password(db, user, request, response)


@router.post("/mfa")
def mfa_login(payload: MfaIn, request: Request, response: Response, db: Session = Depends(get_db)):
    user = _step_user(db, payload.step_token, "mfa")
    auth_limit(request, "mfa", user.id, limit=LOCK_AFTER, window_secs=LOCK_MINUTES * 60)
    if not security.verify_second_factor(user, payload.code):
        db.commit()
        audit.log(db, "auth.mfa_failed", user=user, ip=_ip(request))
        raise HTTPException(status_code=401, detail="Invalid code")
    db.commit()
    return _start_session(db, user, request, response, mfa=True)


# ------------------------------------------------------------------ authenticator app
@router.post("/mfa/setup")
def mfa_setup(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """A new secret to scan. Not active until a code from it is confirmed."""
    import pyotp
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="An authenticator app is already set up")
    secret = pyotp.random_base32()
    security.set_totp_secret(user, secret)
    db.commit()
    from ..config import settings
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.APP_NAME)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": _qr_svg(uri)}


def _qr_svg(text: str) -> str:
    """The QR code drawn on the server, so the secret never goes to a
    third-party QR service."""
    import io

    import qrcode
    import qrcode.image.svg
    buf = io.BytesIO()
    qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2).save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.index("<svg"):]


@router.post("/mfa/enable")
def mfa_enable(payload: CodeIn, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    if user.mfa_enabled or not user.totp_secret or getattr(request.state, "session", None) is None:
        raise HTTPException(status_code=400, detail="Start the setup first")
    rate_limit(request, f"mfa-enable:{user.id}", 10, 900)
    if not security.verify_totp(user, payload.code):
        raise HTTPException(status_code=400, detail="That code doesn't match. Check the time on your phone and try again")
    user.mfa_enabled = True
    codes = security.new_recovery_codes(user)
    request.state.session.mfa_at = datetime.utcnow()
    db.commit()
    audit.log_request(db, request, "auth.mfa_enabled", user)
    return {"ok": True, "recovery_codes": codes}


@router.post("/mfa/recovery-codes")
def mfa_recovery_codes(payload: CodeIn, request: Request, db: Session = Depends(get_db),
                       user: models.User = Depends(get_current_user)):
    """New recovery codes (the old ones stop working). Needs a current code."""
    rate_limit(request, f"step-up:{user.id}", 10, 900)
    if not user.mfa_enabled or not security.verify_totp(user, payload.code):
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid code")
    codes = security.new_recovery_codes(user)
    db.commit()
    audit.log_request(db, request, "auth.recovery_codes", user)
    return {"recovery_codes": codes}


@router.post("/mfa/disable")
def mfa_disable(payload: CodeIn, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    if user.role in ("owner", "admin"):
        raise HTTPException(status_code=400, detail="Owners and admins must keep an authenticator app")
    rate_limit(request, f"step-up:{user.id}", 10, 900)
    if not user.mfa_enabled or not security.verify_second_factor(user, payload.code):
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid code")
    security.set_totp_secret(user, None)
    user.mfa_enabled, user.recovery_codes = False, None
    db.commit()
    audit.log_request(db, request, "auth.mfa_disabled", user)
    return {"ok": True}


@router.post("/step-up")
def step_up(payload: CodeIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(get_current_user)):
    """Confirm an authenticator code before a sensitive change."""
    row = getattr(request.state, "session", None)
    if row is None or not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Set up an authenticator app first")
    rate_limit(request, f"step-up:{user.id}", 10, 900)
    if not security.verify_second_factor(user, payload.code):
        db.commit()
        audit.log_request(db, request, "auth.step_up_failed", user)
        raise HTTPException(status_code=401, detail="Invalid code")
    row.mfa_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ password and sessions
@router.post("/password")
def change_password(payload: PasswordChangeIn, request: Request, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    auth_limit(request, "password", user.id)
    if not passwords.verify(payload.current_password, user.password_hash):
        audit.log_request(db, request, "auth.password_change_failed", user)
        raise HTTPException(status_code=400, detail="Your current password is wrong")
    try:
        passwords.check_policy(payload.new_password, email=user.email, old_password=payload.current_password)
    except passwords.PasswordError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    user.password_hash = passwords.hash_password(payload.new_password)
    db.commit()
    row = getattr(request.state, "session", None)
    ended = sessions.revoke_user(db, user, "password_change", keep=row.id if row else None)
    audit.log_request(db, request, "auth.password_changed", user, {"other_sessions_ended": ended})
    return {"ok": True, "other_sessions_ended": ended}


@router.get("/sessions")
def list_sessions(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    current = getattr(request.state, "session", None)
    rows = (db.query(models.UserSession)
            .filter(models.UserSession.user_id == user.id, models.UserSession.revoked_at.is_(None))
            .order_by(models.UserSession.last_used_at.desc()).all())
    return [{"id": r.id, "device": r.device, "ip": r.ip, "current": bool(current and r.id == current.id),
             "created_at": r.created_at.isoformat() + "Z", "last_used_at": r.last_used_at.isoformat() + "Z"}
            for r in rows if sessions.is_live(r)]


@router.delete("/sessions/{session_id}")
def end_session(session_id: str, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    row = (db.query(models.UserSession)
           .filter(models.UserSession.id == session_id, models.UserSession.user_id == user.id).first())
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    sessions.revoke(db, row, "signed_out")
    audit.log_request(db, request, "auth.session_ended", user, {"session": row.id})
    return {"ok": True}


@router.post("/sessions/revoke")
def revoke_other_sessions(request: Request, db: Session = Depends(get_db),
                          user: models.User = Depends(get_current_user)):
    """Sign out everywhere else. This browser stays signed in."""
    row = getattr(request.state, "session", None)
    ended = sessions.revoke_user(db, user, "signed_out_everywhere", keep=row.id if row else None)
    audit.log_request(db, request, "auth.sessions_revoked", user, {"ended": ended})
    return {"ok": True, "ended": ended}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        user = get_current_user(request, None, db)
        row = getattr(request.state, "session", None)
        if row:
            sessions.revoke(db, row, "logout")
        audit.log_request(db, request, "auth.logout", user)
    except HTTPException:
        pass
    sessions.clear_cookies(response)
    return {"ok": True}


@router.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return me_out(user)
