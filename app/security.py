"""Signed tokens, authenticator-app (TOTP) checks and recovery codes."""
import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta

import pyotp
from jose import JWTError, jwt

from .config import settings

ALGORITHM = "HS256"


def create_access_token(*, user_id: str, tenant_id: str, session_id: str, role: str, version: int = 0) -> str:
    """Short-lived (ACCESS_TOKEN_MINUTES). Names its session, so ending the
    session ends the token, and its company: the request is refused if that
    stops matching the user's company."""
    payload = {"sub": user_id, "tid": tenant_id, "sid": session_id, "role": role, "typ": "access",
               "tv": version or 0, "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_MINUTES)}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_step_token(*, user_id: str, purpose: str, minutes: int = 10) -> str:
    """Between login steps (new password, authenticator code). Not a session:
    it opens nothing but the next step."""
    payload = {"sub": user_id, "typ": purpose, "exp": datetime.utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def platform_fingerprint() -> str:
    """Goes into platform-admin tokens: changing ADMIN_PASSWORD signs them out."""
    return hmac.new(settings.SECRET_KEY.encode(), settings.ADMIN_PASSWORD.encode(), hashlib.sha256).hexdigest()[:16]


def create_platform_token() -> str:
    payload = {"typ": "platform", "pw": platform_fingerprint(),
               "exp": datetime.utcnow() + timedelta(hours=2)}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, allowed_types: tuple[str, ...] = ("access",)) -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    return payload if payload.get("typ") in allowed_types else None


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------- TOTP
def totp_secret(user) -> str | None:
    from . import crypto
    return crypto.decrypt(user.totp_secret) if user.totp_secret else None


def set_totp_secret(user, secret: str | None) -> None:
    """Seeds are stored encrypted: a database dump alone can't mint codes."""
    from . import crypto
    user.totp_secret = crypto.encrypt(secret) if secret else None
    user.totp_last_step = None


def verify_totp(user, code: str) -> bool:
    """A 6-digit code (±1 step for clock drift). Each time-step is accepted
    once, so a code seen over someone's shoulder can't be replayed. The
    caller commits."""
    secret = totp_secret(user)
    code = (code or "").strip().replace(" ", "")
    if not secret or not re.fullmatch(r"\d{6}", code):
        return False
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in (0, -1, 1):
        step = totp.timecode(datetime.utcfromtimestamp(now)) + offset
        if hmac.compare_digest(totp.generate_otp(step), code):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False
            user.totp_last_step = step
            return True
    return False


def new_recovery_codes(user, count: int = 10) -> list[str]:
    """One-time codes for a lost phone. Only their hashes are stored."""
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(count)]
    user.recovery_codes = [token_hash(c) for c in codes]
    return codes


def use_recovery_code(user, code: str) -> bool:
    digest = token_hash((code or "").strip().lower())
    remaining = list(user.recovery_codes or [])
    for stored in remaining:
        if hmac.compare_digest(stored, digest):
            remaining.remove(stored)
            user.recovery_codes = remaining  # new list: JSON column change is tracked
            return True
    return False


def verify_second_factor(user, code: str) -> bool:
    """An authenticator code, or one of the recovery codes."""
    code = (code or "").strip()
    return verify_totp(user, code) if re.fullmatch(r"\d{6}", code.replace(" ", "")) else use_recovery_code(user, code)
