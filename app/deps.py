"""Request dependencies: auth, tenant scoping, rate limiting, domain validation.

Every company's data is filtered on the signed-in user's tenant_id (see the
tenant_* helpers and the per-router queries). Anonymous public scans
(tenant_id NULL) are only reachable by their unguessable id.
"""
import hashlib
import ipaddress
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import idna
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .database import get_db

bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------- domain input
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".onion", ".test", ".example", ".invalid")


def normalize_domain(raw: str) -> str:
    """Validate and normalize a user-supplied domain. Raises 400 on bad input."""
    if not raw or len(raw) > 2048:
        raise HTTPException(status_code=400, detail="Invalid domain")
    domain = raw.strip().lower()
    # Allow pasted URLs / emails: extract host part
    domain = re.sub(r"^[a-z][a-z0-9+.-]*://", "", domain)
    domain = domain.split("/")[0].split("?")[0].split("#")[0].split("@")[-1].split(":")[0]
    domain = domain.strip().rstrip(".")
    try:
        domain = idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        raise HTTPException(status_code=400, detail="Invalid domain name")
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain name")
    try:  # IP literals are not valid scan targets
        ipaddress.ip_address(domain)
        raise HTTPException(status_code=400, detail="IP addresses cannot be scanned")
    except ValueError:
        pass
    if domain.endswith(_BLOCKED_SUFFIXES) or domain in ("localhost",):
        raise HTTPException(status_code=400, detail="Domain not allowed")
    return domain


def _domain_exists_in_dns(domain: str) -> bool:
    """True if the name exists in DNS even without an A/AAAA record
    (mail-only domains publish MX/TXT but no web address)."""
    import dns.resolver

    for rtype in ("SOA", "MX", "TXT", "NS"):
        try:
            dns.resolver.resolve(domain, rtype, lifetime=5)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            continue
    return False


def assert_public_target(domain: str) -> None:
    """SSRF guard: refuse to scan hosts that resolve to non-public addresses
    (private, loopback, link-local, CGNAT, reserved, multicast, IPv4-mapped)."""
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        # No address records: still scannable if the domain exists (its web
        # checks will simply report the host as unreachable).
        if _domain_exists_in_dns(domain):
            return
        raise HTTPException(status_code=400, detail="Domain does not resolve")
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise HTTPException(status_code=400, detail="Domain resolves to a non-public address")


# ---------------------------------------------------------------- auth
# Owners and admins must have an authenticator app. Until they do, these are
# the only things their session can reach.
MFA_SETUP_PATHS = {"/dashboard", "/api/auth/me", "/api/auth/mfa/setup", "/api/auth/mfa/enable",
                   "/api/auth/logout"}
STEP_UP_MINUTES = 10


def _unauthorized(detail: str = "Not authenticated"):
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def _security_event(db: Session, request: Request, action: str, claims: dict) -> None:
    """Audit a forged or mismatched token as critical, under the company it
    pointed at when that company exists."""
    from . import audit
    tid = claims.get("tid") if isinstance(claims.get("tid"), str) else None
    if tid and not db.get(models.Tenant, tid):
        tid = None
    audit.log(db, action, tenant_id=tid, ip=request.client.host if request.client else None,
              detail={"severity": "critical", "path": request.url.path,
                      "claimed_user": str(claims.get("sub"))[:40], "claimed_tenant": str(claims.get("tid"))[:40]})


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """The signed-in user, from an API key or a session's access token.
    Everything the user can reach is filtered on user.tenant_id."""
    from jose import ExpiredSignatureError, JWTError, jwt as jose_jwt

    from . import sessions
    from .security import ALGORITHM
    # 1) API key (scripts, SIEM, MCP clients): X-API-Key, or
    # "Authorization: Bearer plk_..." which is what MCP clients send.
    api_key = request.headers.get("x-api-key")
    if not api_key and credentials and credentials.scheme.lower() == "bearer" \
            and credentials.credentials.startswith("plk_"):
        api_key = credentials.credentials
    if api_key:
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        key = (db.query(models.ApiKey)
               .filter(models.ApiKey.key_hash == digest, models.ApiKey.is_active.is_(True)).first())
        user = db.get(models.User, key.user_id) if key else None
        # The key acts as the user who made it, in that user's company, and
        # stops working when the user is suspended or removed.
        if not key or not user or user.tenant_id != key.tenant_id or not sessions.account_usable(user):
            raise _unauthorized("Invalid API key")
        key.last_used_at = datetime.utcnow()
        db.commit()
        request.state.auth_method = "api_key"
        request.state.session = None
        return user
    # 2) Session access token: Bearer header or httpOnly cookie (browser pages)
    token = getattr(request.state, "access_token", None)  # just refreshed by the middleware
    if not token and credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise _unauthorized()
    try:
        claims = jose_jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise _unauthorized("Session expired")
    except JWTError:
        # Not signed by this server: someone edited a token (e.g. its company).
        try:
            unverified = jose_jwt.get_unverified_claims(token)
        except JWTError:
            raise _unauthorized("Invalid session")
        _security_event(db, request, "security.token_tampered", unverified)
        raise HTTPException(status_code=403, detail="Invalid session")
    if claims.get("typ") != "access":
        raise _unauthorized("Invalid session")
    row = db.get(models.UserSession, claims.get("sid") or "")
    if not sessions.is_live(row) or row.user_id != claims.get("sub"):
        raise _unauthorized("Session was signed out")
    user = db.get(models.User, row.user_id)
    if not user or not sessions.account_usable(user) or claims.get("tv", 0) != (user.token_version or 0):
        raise _unauthorized("Session was signed out")
    if claims.get("tid") != user.tenant_id or row.tenant_id != user.tenant_id:
        # A genuine token whose company no longer matches the account's.
        _security_event(db, request, "security.cross_tenant", claims)
        sessions.revoke(db, row, "cross_tenant")
        raise HTTPException(status_code=403, detail="Invalid session")
    now = datetime.utcnow()
    if now - row.last_used_at > timedelta(seconds=60):  # idle timer, without a write per request
        row.last_used_at = now
        db.commit()
    if user.role in ("owner", "admin") and not user.mfa_enabled and request.url.path not in MFA_SETUP_PATHS:
        raise HTTPException(status_code=403, detail="mfa_setup_required")
    request.state.auth_method = "cookie" if request.cookies.get("access_token") == token else "bearer"
    request.state.session = row
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    """Owners and admins: company settings and user management."""
    if user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def require_owner(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Owner role required")
    return user


def require_step_up(request: Request, user: models.User = Depends(require_admin)) -> models.User:
    """Sensitive changes (users, roles, the mail server, exports) need an
    authenticator code from the last few minutes, even mid-session: a stolen
    session cookie alone can't hand out accounts."""
    row = getattr(request.state, "session", None)
    if row is None:
        raise HTTPException(status_code=403, detail="Not available with an API key")
    if not row.mfa_at or datetime.utcnow() - row.mfa_at > timedelta(minutes=STEP_UP_MINUTES):
        raise HTTPException(status_code=403, detail="step_up_required")
    return user


def tenant_scans(db: Session, user: models.User):
    return db.query(models.Scan).filter(models.Scan.tenant_id == user.tenant_id)


def tenant_monitors(db: Session, user: models.User):
    return db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id)


def tenant_alerts(db: Session, user: models.User):
    return db.query(models.Alert).filter(models.Alert.tenant_id == user.tenant_id)


# ---------------------------------------------------------------- rate limiting
# In-process sliding window by default (one worker). With several workers or
# instances set RATE_LIMIT_STORAGE=database so limits are shared.
_hits: dict[str, deque] = {}
_hits_lock = threading.Lock()
_last_sweep = 0.0


def _sweep(now: float, max_window: int = 3600) -> None:
    """Drop idle buckets so the table can't grow without bound."""
    global _last_sweep
    if now - _last_sweep < 300:
        return
    _last_sweep = now
    cutoff = now - max_window
    for k in [k for k, b in _hits.items() if not b or b[-1] < cutoff]:
        del _hits[k]


def _db_rate_limit(key: str, limit: int, window_secs: int) -> None:
    """Fixed-window counter in the database: shared by every worker/instance."""
    from sqlalchemy import update
    from sqlalchemy.exc import IntegrityError

    from .database import SessionLocal

    now = datetime.utcnow()
    window = now - timedelta(seconds=window_secs)
    key = key[:200]
    db = SessionLocal()
    try:
        bumped = db.execute(
            update(models.RateCounter)
            .where(models.RateCounter.key == key, models.RateCounter.window_start >= window,
                   models.RateCounter.count < limit)
            .values(count=models.RateCounter.count + 1)).rowcount
        if not bumped:
            row = db.get(models.RateCounter, key)
            if row and row.window_start >= window:
                db.rollback()
                raise HTTPException(status_code=429, detail="Rate limit exceeded, try again later")
            if row:  # window expired: start a new one
                row.window_start, row.count = now, 1
            else:
                db.add(models.RateCounter(key=key, window_start=now, count=1))
        try:
            db.commit()
        except IntegrityError:  # concurrent first hit; count it next time
            db.rollback()
    finally:
        db.close()


def rate_limit(request: Request, key: str, limit: int, window_secs: int = 3600) -> None:
    if settings.RATE_LIMIT_STORAGE == "database":
        return _db_rate_limit(key, limit, window_secs)
    now = time.time()
    with _hits_lock:
        _sweep(now)
        bucket = _hits.setdefault(key, deque())
        cutoff = now - window_secs
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded, try again later")
        bucket.append(now)


def client_ip(request: Request) -> str:
    # Behind a reverse proxy, run uvicorn with --proxy-headers so this is the
    # real client address rather than the proxy's.
    return request.client.host if request.client else "unknown"


def public_scan_limit(request: Request) -> None:
    rate_limit(request, f"scan:{client_ip(request)}", settings.SCAN_RATE_LIMIT_PER_HOUR)


def auth_limit(request: Request, bucket: str, ident: str = "", limit: int = 10,
               window_secs: int = 900) -> None:
    """Brute-force brake for credential endpoints: per client IP, and per
    account identifier when one is given (stops distributed guessing)."""
    rate_limit(request, f"{bucket}:ip:{client_ip(request)}", limit * 3, window_secs)
    if ident:
        rate_limit(request, f"{bucket}:id:{ident}", limit, window_secs)

