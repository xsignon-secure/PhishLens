"""Password hashing, JWT session tokens and TOTP checks."""
import hmac
import re
import time
from datetime import datetime, timedelta

import pyotp

import bcrypt
from jose import JWTError, jwt

from .config import settings

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    pw = password.encode("utf-8")
    if len(pw) > 72:
        raise ValueError("Password must be at most 72 characters")
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(*, user_id: str, tenant_id: str, version: int = 0, sso: bool = False) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "tid": tenant_id, "exp": expire, "typ": "access", "tv": version or 0}
    if sso:  # the identity provider did the login (and its own MFA)
        payload["amr"] = "sso"
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_token(*, user_id: str) -> str:
    """Short-lived token for the second step of MFA login. Not a session."""
    expire = datetime.utcnow() + timedelta(minutes=10)
    payload = {"sub": user_id, "exp": expire, "typ": "mfa"}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, allowed_types: tuple[str, ...] = ("access",)) -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("typ") not in allowed_types:
            return None
        return payload
    except JWTError:
        return None


# ---------------------------------------------------------------- TOTP
def totp_secret(user) -> str | None:
    """The user's TOTP seed. Stored encrypted; seeds saved before encryption
    was added are plain base32 and still accepted (re-encrypted on next use)."""
    from . import crypto
    if not user.totp_secret:
        return None
    return crypto.decrypt(user.totp_secret) or (
        user.totp_secret if re.fullmatch(r"[A-Z2-7]{16,64}", user.totp_secret) else None)


def set_totp_secret(user, secret: str | None) -> None:
    from . import crypto
    user.totp_secret = crypto.encrypt(secret) if secret else None
    user.totp_last_step = None


def verify_totp(user, code: str) -> bool:
    """Check a 6-digit code (±1 step for clock drift) and refuse replays: each
    time-step can be used once. The caller commits."""
    secret = totp_secret(user)
    code = (code or "").strip()
    if not secret or not re.fullmatch(r"\d{6}", code):
        return False
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in (0, -1, 1):
        step = totp.timecode(datetime.utcfromtimestamp(now)) + offset
        if hmac.compare_digest(totp.generate_otp(step), code):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False  # already used
            user.totp_last_step = step
            if secret == user.totp_secret:  # legacy plaintext seed
                set_totp_secret(user, secret)
                user.totp_last_step = step
            return True
    return False
