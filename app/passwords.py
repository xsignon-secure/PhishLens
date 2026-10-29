"""Password hashing and policy.

Argon2id for new hashes (memory-hard, so GPU guessing is slow). Hashes from
older versions (bcrypt) still verify and are upgraded on the next login.
"""
import hashlib
import logging
import secrets
import string

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings

log = logging.getLogger("phishlens.passwords")

_hasher = PasswordHasher()  # argon2id, RFC 9106 low-memory profile
# Verified against when the email is unknown, so a login for a missing account
# takes as long as one for a real account (no account discovery by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_LENGTH = 12
MAX_LENGTH = 128

# Seen first in every breach list; refused even when the breach check is off.
_COMMON = {
    "123456789012", "1234567890123", "password1234", "passwordpassword", "qwertyuiopas",
    "qwerty123456", "iloveyou1234", "welcome12345", "letmein12345", "administrator",
    "changeme1234", "abcdefghijkl", "111111111111", "000000000000", "aaaaaaaaaaaa",
    "phishlens123", "password123!", "Password1234", "P@ssw0rd1234", "welcome@1234",
}


class PasswordError(ValueError):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify(password: str, password_hash: str | None) -> bool:
    """Constant-time check. Unknown users still pay for one hash."""
    if not password_hash or password_hash.startswith("!"):
        _safe_verify(_DUMMY_HASH, password)
        return False
    if password_hash.startswith("$2"):  # bcrypt from an older version
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode()[:72], password_hash.encode())
        except Exception:
            return False
    return _safe_verify(password_hash, password)


def _safe_verify(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    if password_hash.startswith("$2"):
        return True
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def check_policy(password: str, *, email: str | None = None, old_password: str | None = None) -> None:
    """NIST 800-63B: length over composition rules, and no known-breached
    passwords. Raises PasswordError with a message for the user."""
    if len(password) < MIN_LENGTH:
        raise PasswordError(f"Use at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        raise PasswordError(f"Use at most {MAX_LENGTH} characters")
    if old_password is not None and password == old_password:
        raise PasswordError("Choose a password different from the temporary one")
    lowered = password.lower()
    if lowered in {c.lower() for c in _COMMON} or len(set(password)) < 4:
        raise PasswordError("This password is too easy to guess")
    if email and email.split("@")[0].lower() in lowered and len(email.split("@")[0]) >= 4:
        raise PasswordError("Don't use your email address in your password")
    if settings.PASSWORD_BREACH_CHECK and breached(password):
        raise PasswordError("This password has appeared in a data breach. Choose another one")


def breached(password: str) -> bool:
    """Have I Been Pwned range query (k-anonymity: only 5 hex characters of
    the SHA-1 are sent). Fails open: an outage must not block logins."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    try:
        r = httpx.get(f"https://api.pwnedpasswords.com/range/{digest[:5]}",
                      headers={"Add-Padding": "true"}, timeout=4)
        r.raise_for_status()
    except Exception as exc:
        log.info("breach check unavailable: %s", exc)
        return False
    suffix = digest[5:]
    for line in r.text.splitlines():
        found, _, count = line.partition(":")
        if found.strip() == suffix and count.strip() not in ("", "0"):
            return True
    return False


def temporary_password() -> str:
    """16 random characters, without look-alikes (0/O, 1/l/I) so they can be
    typed from an email."""
    alphabet = "".join(c for c in string.ascii_letters + string.digits if c not in "0O1lI")
    return "".join(secrets.choice(alphabet) for _ in range(16))
