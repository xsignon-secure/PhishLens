"""Encryption at rest for third-party secrets tenants give us (SSO client
secrets, DNS provider tokens). Keyed from SECRET_KEY, so rotating SECRET_KEY
makes stored secrets unreadable: tenants then re-enter them."""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _fernet() -> Fernet:
    key = hashlib.sha256(b"phishlens-secrets-v1:" + settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None
