"""Single sign-on with OpenID Connect (Okta, Microsoft Entra ID, Google
Workspace, Auth0, OneLogin, JumpCloud, Keycloak...).

Authorization-code flow with PKCE. The tenant registers PhishLens as an app in
its identity provider and gives us the issuer URL, client id and secret; users
whose email is on the tenant's SSO domain sign in through the IdP.
"""
import base64
import hashlib
import secrets
import time
import urllib.parse

import httpx
from jose import jwt
from jose.exceptions import JWTError

from . import crypto, webhooks
from .config import settings

STATE_TTL = 600
_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}
CACHE_SECONDS = 3600


class SsoError(Exception):
    pass


def redirect_uri() -> str:
    return f"{settings.APP_URL}/api/auth/sso/callback"


def _get_json(url: str) -> dict:
    # The issuer is tenant-supplied: same public-https rule as webhooks, and
    # no redirects, so it can't be pointed at internal services.
    if not url.startswith("https://") or not webhooks.url_allowed(url):
        raise SsoError("Identity provider URL must be public https")
    try:
        r = httpx.get(url, timeout=10, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise SsoError(f"Identity provider unreachable: {exc}") from exc
    if r.status_code != 200:
        raise SsoError(f"Identity provider returned {r.status_code} for {url}")
    try:
        return r.json()
    except ValueError as exc:
        raise SsoError("Identity provider returned invalid JSON") from exc


def discover(issuer: str) -> dict:
    issuer = issuer.rstrip("/")
    hit = _discovery_cache.get(issuer)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    doc = _get_json(issuer + "/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(doc.get(key, "")).startswith("https://"):
            raise SsoError(f"Discovery document has no https {key}")
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise SsoError("Discovery document's issuer doesn't match the configured issuer")
    _discovery_cache[issuer] = (time.time(), doc)
    return doc


def _jwks(uri: str, refresh: bool = False) -> dict:
    hit = _jwks_cache.get(uri)
    if hit and not refresh and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    keys = _get_json(uri)
    _jwks_cache[uri] = (time.time(), keys)
    return keys


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def start(tenant) -> tuple[str, str]:
    """Returns (IdP authorization URL, signed state cookie value)."""
    doc = discover(tenant.sso_issuer)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = _pkce()
    cookie = jwt.encode({"tid": tenant.id, "state": state, "nonce": nonce, "v": verifier,
                         "exp": int(time.time()) + STATE_TTL, "typ": "sso_state"},
                        settings.SECRET_KEY, algorithm="HS256")
    params = {"response_type": "code", "client_id": tenant.sso_client_id,
              "redirect_uri": redirect_uri(), "scope": "openid email profile",
              "state": state, "nonce": nonce, "code_challenge": challenge,
              "code_challenge_method": "S256"}
    return doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(params), cookie


def read_state(cookie: str | None) -> dict:
    if not cookie:
        raise SsoError("Sign-in session expired: start again")
    try:
        data = jwt.decode(cookie, settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as exc:
        raise SsoError("Sign-in session expired: start again") from exc
    if data.get("typ") != "sso_state":
        raise SsoError("Invalid sign-in session")
    return data


def finish(tenant, code: str, state: dict) -> dict:
    """Exchange the code and verify the ID token. Returns its claims."""
    doc = discover(tenant.sso_issuer)
    secret = crypto.decrypt(tenant.sso_client_secret) or ""
    if not webhooks.url_allowed(doc["token_endpoint"]):
        raise SsoError("Token endpoint must be public https")
    try:
        r = httpx.post(doc["token_endpoint"], timeout=10, follow_redirects=False, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(),
            "client_id": tenant.sso_client_id, "client_secret": secret,
            "code_verifier": state["v"]})
    except httpx.HTTPError as exc:
        raise SsoError(f"Identity provider unreachable: {exc}") from exc
    if r.status_code != 200:
        raise SsoError("Identity provider rejected the sign-in")
    id_token = (r.json() or {}).get("id_token")
    if not id_token:
        raise SsoError("Identity provider returned no ID token")
    claims = verify_id_token(id_token, doc, tenant.sso_client_id, state["nonce"])
    email = str(claims.get("email") or claims.get("preferred_username") or "").lower().strip()
    if "@" not in email:
        raise SsoError("Identity provider didn't share an email address")
    if claims.get("email_verified") is False:
        raise SsoError("Your email isn't verified at the identity provider")
    if email.rsplit("@", 1)[1] != (tenant.sso_email_domain or "").lower():
        raise SsoError(f"Only @{tenant.sso_email_domain} accounts can sign in here")
    claims["email"] = email
    return claims


def verify_id_token(id_token: str, doc: dict, client_id: str, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(id_token)
    except JWTError as exc:
        raise SsoError("Malformed ID token") from exc
    alg = header.get("alg", "")
    if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256"):
        raise SsoError(f"Unsupported ID token algorithm {alg}")
    for refresh in (False, True):  # keys rotate: refetch once on a miss
        keys = _jwks(doc["jwks_uri"], refresh=refresh)
        key = next((k for k in keys.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if key:
            break
    else:
        raise SsoError("ID token signed with an unknown key")
    try:
        claims = jwt.decode(id_token, key, algorithms=[alg], audience=client_id,
                            issuer=doc["issuer"], options={"verify_at_hash": False})
    except JWTError as exc:
        raise SsoError(f"ID token rejected: {exc}") from exc
    if claims.get("nonce") != nonce:
        raise SsoError("ID token nonce mismatch")
    return claims
