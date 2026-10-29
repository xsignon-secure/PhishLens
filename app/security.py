"""Admin session tokens (JWT)."""
from datetime import datetime, timedelta

from jose import JWTError, jwt

from .config import settings

ALGORITHM = "HS256"


def create_access_token(*, user_id: str, tenant_id: str, version: int = 0) -> str:
    """An admin session. Carries a fingerprint of ADMIN_PASSWORD, so changing
    the password signs every session out."""
    from .workspace import password_fingerprint
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "tid": tenant_id, "exp": expire, "typ": "access", "tv": version or 0,
               "pw": password_fingerprint()}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, allowed_types: tuple[str, ...] = ("access",)) -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("typ") not in allowed_types:
            return None
        return payload
    except JWTError:
        return None
