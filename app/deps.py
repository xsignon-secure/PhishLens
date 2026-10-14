"""Request dependencies: auth, tenant scoping, rate limiting, domain validation.

Tenant isolation rule: every database read/write for tenant data goes through
get_current_user(), and filters on tenant_id == user.tenant_id. Anonymous
public scans (tenant_id NULL) are only reachable by their unguessable id.
"""
import hashlib
import ipaddress
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime

import idna
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .database import get_db
from .security import decode_token

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
def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    # 1) API key (automation / SIEM integrations) — explicit header auth
    api_key = request.headers.get("x-api-key")
    if api_key:
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        key = (
            db.query(models.ApiKey)
            .filter(models.ApiKey.key_hash == digest, models.ApiKey.is_active.is_(True))
            .first()
        )
        if not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        key.last_used_at = datetime.utcnow()
        db.commit()
        user = (
            db.query(models.User)
            .filter(models.User.id == key.user_id, models.User.is_active.is_(True))
            .first()
        )
        if not user or user.tenant_id != key.tenant_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        request.state.auth_method = "api_key"
        return user
    # 2) JWT: Bearer header or httpOnly cookie (browser pages)
    token = None
    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    if not token:  # also accept cookie for browser pages
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = (
        db.query(models.User)
        .filter(models.User.id == payload.get("sub"), models.User.is_active.is_(True))
        .first()
    )
    if not user or user.tenant_id != payload.get("tid"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    request.state.auth_method = "cookie" if request.cookies.get("access_token") else "bearer"
    return user


def require_owner(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Owner role required")
    return user


def tenant_scans(db: Session, user: models.User):
    return db.query(models.Scan).filter(models.Scan.tenant_id == user.tenant_id)


def tenant_monitors(db: Session, user: models.User):
    return db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id)


def tenant_alerts(db: Session, user: models.User):
    return db.query(models.Alert).filter(models.Alert.tenant_id == user.tenant_id)


# ---------------------------------------------------------------- rate limiting
# In-process sliding window. Per-worker: move to Redis when running multiple
# workers (see docs/ENTERPRISE.md).
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


def rate_limit(request: Request, key: str, limit: int, window_secs: int = 3600) -> None:
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
