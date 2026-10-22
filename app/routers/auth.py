"""Auth: signup, login (+MFA), logout, password reset, email verification, TOTP MFA."""
import secrets

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import audit, mailer, models, schemas, security, tokens
from ..config import settings
from ..database import get_db
from ..deps import auth_limit, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _user_out(user: models.User) -> schemas.UserOut:
    return schemas.UserOut(
        id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
        tenant_name=user.tenant.name if user.tenant else "",
        is_verified=user.is_verified,
        mfa_enabled=user.mfa_enabled,
    )


def _set_session_cookies(response: Response, token: str) -> None:
    secure = settings.cookie_secure
    response.set_cookie("access_token", token, httponly=True, secure=secure,
                        samesite="lax", max_age=settings.JWT_EXPIRE_MINUTES * 60)
    response.set_cookie("csrf_token", secrets.token_urlsafe(32), secure=secure,
                        samesite="lax", max_age=settings.JWT_EXPIRE_MINUTES * 60)


def _hash_or_400(password: str) -> str:
    try:
        return security.hash_password(password)
    except ValueError as exc:  # e.g. >72 bytes once multi-byte chars are encoded
        raise HTTPException(status_code=400, detail=str(exc))


def _send_verify_email(db: Session, user: models.User) -> None:
    raw = tokens.create(db, "verify_email", ttl_hours=48, user_id=user.id)
    link = f"{settings.APP_URL}/verify?token={raw}"
    mailer.send_email(
        [user.email], "Verify your email",
        f"Welcome to {settings.APP_NAME}.\n\nConfirm your email:\n{link}\n\n"
        f"This link expires in 48 hours.")


@router.post("/signup", status_code=201)
def signup(payload: schemas.SignupIn, request: Request, response: Response,
           db: Session = Depends(get_db)):
    auth_limit(request, "signup", limit=10, window_secs=3600)
    email = payload.email.lower().strip()
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    password_hash = _hash_or_400(payload.password)

    tenant = None
    role = "owner"
    if payload.invite_token:
        # Check the invite matches this email BEFORE consuming it, so a typo
        # in the email doesn't burn the invitee's single-use link.
        inv = tokens.peek(db, payload.invite_token, "invite")
        if not inv or (inv.extra or {}).get("email", "").lower() != email:
            raise HTTPException(status_code=400, detail="Invalid or expired invite")
        inv = tokens.consume(db, payload.invite_token, "invite")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == inv.tenant_id).first() if inv else None
        if not tenant:
            raise HTTPException(status_code=400, detail="Invalid invite")
        role = "member"
        # The invite link was delivered to this address, which proves ownership.
    if tenant is None:
        tenant = models.Tenant(name=payload.company.strip())
        db.add(tenant)
        db.flush()

    user = models.User(
        tenant_id=tenant.id, email=email,
        password_hash=password_hash, role=role, is_verified=(role == "member"))
    db.add(user)
    db.commit()
    db.refresh(user)
    if not user.is_verified:
        _send_verify_email(db, user)
    audit.log_request(db, request, "auth.signup", user,
                      {"via_invite": bool(payload.invite_token)})
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    _set_session_cookies(response, token)
    return schemas.TokenOut(access_token=token, user=_user_out(user))


@router.post("/login")
def login(payload: schemas.LoginIn, request: Request, response: Response,
          db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    auth_limit(request, "login", email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active or not security.verify_password(payload.password, user.password_hash):
        audit.log_request(db, request, "auth.login_failed", detail={"email": email})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")
    if user.tenant and user.tenant.sso_enforced and user.tenant.sso_issuer and user.role != "owner":
        # Owners keep password login as a break-glass path if the IdP is down.
        raise HTTPException(status_code=403, detail="Your organisation requires single sign-on: use 'Sign in with SSO'")
    if user.mfa_enabled:
        audit.log_request(db, request, "auth.mfa_challenged", user)
        return schemas.MfaRequiredOut(mfa_token=security.create_mfa_token(user_id=user.id))
    audit.log_request(db, request, "auth.login", user)
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    _set_session_cookies(response, token)
    return schemas.TokenOut(access_token=token, user=_user_out(user))


@router.post("/mfa/challenge")
def mfa_challenge(payload: schemas.MfaChallengeIn, request: Request,
                  response: Response, db: Session = Depends(get_db)):
    data = security.decode_token(payload.mfa_token, allowed_types=("mfa",))
    if not data:
        raise HTTPException(status_code=401, detail="Invalid MFA session")
    # 6-digit codes are guessable without a brake: cap attempts per account.
    auth_limit(request, "mfa", data.get("sub", ""), limit=5)
    user = db.query(models.User).filter(
        models.User.id == data.get("sub"), models.User.is_active.is_(True)).first()
    if not user or not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(status_code=401, detail="MFA not configured")
    if not pyotp.TOTP(user.totp_secret).verify(payload.code.strip(), valid_window=1):
        audit.log_request(db, request, "auth.mfa_failed", user)
        raise HTTPException(status_code=401, detail="Invalid code")
    audit.log_request(db, request, "auth.login", user, {"mfa": True})
    token = security.create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    _set_session_cookies(response, token)
    return schemas.TokenOut(access_token=token, user=_user_out(user))


@router.post("/mfa/setup")
def mfa_setup(request: Request, db: Session = Depends(get_db),
              user: models.User = Depends(get_current_user)):
    if user.mfa_enabled:
        # Re-running setup used to silently replace the secret and switch MFA
        # off with no password check. Disabling requires the password.
        raise HTTPException(status_code=409, detail="MFA is already enabled; disable it first")
    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.mfa_enabled = False
    db.commit()
    audit.log_request(db, request, "auth.mfa_setup_started", user)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name=settings.APP_NAME)
    return {"secret": secret, "otpauth_url": uri}


@router.post("/mfa/verify")
def mfa_verify(payload: schemas.MfaVerifyIn, request: Request,
               db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    auth_limit(request, "mfa_verify", user.id, limit=10)
    if not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(payload.code.strip(), valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code")
    user.mfa_enabled = True
    db.commit()
    audit.log_request(db, request, "auth.mfa_enabled", user)
    return {"ok": True}


@router.post("/mfa/disable")
def mfa_disable(payload: schemas.MfaDisableIn, request: Request,
                db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    auth_limit(request, "mfa_disable", user.id, limit=5)
    if not security.verify_password(payload.password, user.password_hash):
        # 400, not 401: the session is fine, and the dashboard treats 401 as "log in again".
        raise HTTPException(status_code=400, detail="Invalid password")
    user.mfa_enabled = False
    user.totp_secret = None
    db.commit()
    audit.log_request(db, request, "auth.mfa_disabled", user)
    return {"ok": True}


@router.post("/password/forgot")
def password_forgot(payload: schemas.PasswordForgotIn, request: Request,
                    db: Session = Depends(get_db)):
    # Always 200: never reveal whether the email is registered.
    email = payload.email.lower().strip()
    auth_limit(request, "forgot", email, limit=5, window_secs=3600)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user and user.is_active:
        raw = tokens.create(db, "password_reset", ttl_hours=2, user_id=user.id)
        link = f"{settings.APP_URL}/reset-password?token={raw}"
        mailer.send_email(
            [user.email], "Reset your password",
            f"Reset your {settings.APP_NAME} password:\n{link}\n\n"
            f"Expires in 2 hours. If you didn't ask, ignore this email.")
        audit.log_request(db, request, "auth.password_reset_requested", user)
    return {"ok": True}


@router.post("/password/reset")
def password_reset(payload: schemas.PasswordResetIn, request: Request,
                   db: Session = Depends(get_db)):
    auth_limit(request, "reset", limit=10)
    new_hash = _hash_or_400(payload.new_password)
    tok = tokens.consume(db, payload.token, "password_reset")
    if not tok:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.id == tok.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.password_hash = new_hash
    user.mfa_enabled = False  # reset kills MFA; user re-enrolls
    user.totp_secret = None
    db.commit()
    audit.log_request(db, request, "auth.password_reset", user)
    return {"ok": True}


@router.post("/verify")
def verify_email(payload: schemas.VerifyEmailIn, request: Request,
                 db: Session = Depends(get_db)):
    # The emailed token itself proves ownership of the address, so no session
    # is required: the link must work in a fresh browser or after the
    # 60-minute session has expired.
    auth_limit(request, "verify", limit=20)
    tok = tokens.consume(db, payload.token, "verify_email")
    user = db.query(models.User).filter(
        models.User.id == tok.user_id, models.User.is_active.is_(True)).first() if tok else None
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user.is_verified = True
    db.commit()
    audit.log_request(db, request, "auth.email_verified", user)
    return {"ok": True}


@router.post("/verify/resend")
def verify_resend(request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    auth_limit(request, "verify_resend", user.id, limit=5, window_secs=3600)
    if not user.is_verified:
        _send_verify_email(db, user)
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response,
           db: Session = Depends(get_db)):
    try:
        user = get_current_user(request, None, db)
        audit.log_request(db, request, "auth.logout", user)
    except Exception:
        pass
    secure = settings.cookie_secure
    response.delete_cookie("access_token", httponly=True, secure=secure, samesite="lax")
    response.delete_cookie("csrf_token", secure=secure, samesite="lax")
    return {"ok": True}


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return _user_out(user)
