"""Password hashing and JWT session tokens."""
from datetime import datetime, timedelta

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


def create_access_token(*, user_id: str, tenant_id: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "tid": tenant_id, "exp": expire, "typ": "access"}
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
