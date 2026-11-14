"""Sender reputation from the mailbox providers themselves.

- Google Postmaster Tools: domain and IP reputation, user-reported spam rate
  and SPF/DKIM/DMARC pass ratios as Gmail sees them. The company connects
  its Google account (read-only scope) once; Postmaster only has data for
  domains verified there and sending enough mail to Gmail (roughly 100+
  messages a day).
- Microsoft SNDS: per-IP filter result (green/yellow/red), complaint rate and
  spam-trap hits at Outlook.com, plus blocked IPs. The company pastes its SNDS
  automated access key.

Both refresh once a day with the scheduled jobs. The team gets an email (and
an alert on the domain's monitor) when Gmail rates a domain low or bad, the
spam rate passes Gmail's 0.3% limit, or Outlook marks an IP red or blocks it.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import logging
import secrets
import time
import urllib.parse
from datetime import date, datetime, timedelta

import httpx
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import crypto, mailer, models
from .config import settings

log = logging.getLogger("phishlens.sender_reputation")

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE = "https://oauth2.googleapis.com/revoke"
POSTMASTER = "https://gmailpostmastertools.googleapis.com/v1"
SCOPE = "https://www.googleapis.com/auth/postmaster.readonly"
SNDS_DATA = "https://sendersupport.olc.protection.outlook.com/snds/data.aspx"
SNDS_STATUS = "https://sendersupport.olc.protection.outlook.com/snds/ipStatus.aspx"
DAYS = 30
REFRESH_EVERY = timedelta(hours=20)
SPAM_LIMIT = 0.003     # Gmail's bulk sender requirement: stay below 0.3%
SPAM_WARN = 0.001      # and ideally below 0.1%
BAD_REPUTATION = {"LOW", "BAD"}
TIMEOUT = 15
STATE_TTL = 600


class ReputationError(Exception):
    pass


# ------------------------------------------------------------------ Google OAuth
def google_configured() -> bool:
    return bool(settings.GOOGLE_POSTMASTER_CLIENT_ID and settings.GOOGLE_POSTMASTER_CLIENT_SECRET)


def redirect_uri() -> str:
    return settings.APP_URL.rstrip("/") + "/reputation/google/callback"


def google_start(tenant: models.Tenant, user: models.User) -> tuple[str, str]:
    """(Google consent URL, signed state cookie value)."""
    if not google_configured():
        raise ReputationError("Google Postmaster isn't set up on this server (GOOGLE_POSTMASTER_CLIENT_ID)")
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    cookie = jwt.encode({"tid": tenant.id, "uid": user.id, "state": state, "v": verifier,
                         "exp": int(time.time()) + STATE_TTL, "typ": "postmaster_state"},
                        settings.SECRET_KEY, algorithm="HS256")
    params = {"response_type": "code", "client_id": settings.GOOGLE_POSTMASTER_CLIENT_ID,
              "redirect_uri": redirect_uri(), "scope": SCOPE + " email", "state": state,
              "access_type": "offline", "prompt": "consent", "code_challenge": challenge,
              "code_challenge_method": "S256", "include_granted_scopes": "false"}
    return GOOGLE_AUTH + "?" + urllib.parse.urlencode(params), cookie


def read_state(cookie: str | None) -> dict:
    try:
        data = jwt.decode(cookie or "", settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as exc:
        raise ReputationError("The Google sign-in took too long: start again") from exc
    if data.get("typ") != "postmaster_state":
        raise ReputationError("Invalid sign-in state")
    return data


def google_finish(db: Session, tenant: models.Tenant, code: str, state: dict, transport=None) -> str:
    """Exchange the code; store the refresh token encrypted. Returns the Google account's email."""
    with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
        r = c.post(GOOGLE_TOKEN, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(),
            "client_id": settings.GOOGLE_POSTMASTER_CLIENT_ID,
            "client_secret": settings.GOOGLE_POSTMASTER_CLIENT_SECRET, "code_verifier": state["v"]})
    if r.status_code != 200:
        raise ReputationError(f"Google refused the sign-in (HTTP {r.status_code})")
    data = r.json()
    refresh = data.get("refresh_token")
    if not refresh:
        raise ReputationError("Google didn't give offline access: remove PhishLens from your Google account "
                              "permissions and connect again")
    if SCOPE not in (data.get("scope") or ""):
        raise ReputationError("Allow access to Postmaster Tools data to connect")
    email = None
    try:
        claims = jwt.get_unverified_claims(data.get("id_token") or "")
        email = claims.get("email")
    except JWTError:
        pass
    tenant.postmaster_token = crypto.encrypt(refresh)
    tenant.postmaster_email = (email or "")[:254] or None
    db.commit()
    return email or ""


def google_disconnect(db: Session, tenant: models.Tenant, transport=None) -> None:
    token = crypto.decrypt(tenant.postmaster_token)
    if token:
        try:
            with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
                c.post(GOOGLE_REVOKE, data={"token": token})
        except httpx.HTTPError:
            pass  # removing it here matters more than telling Google
    tenant.postmaster_token = None
    tenant.postmaster_email = None
    rep = dict(tenant.sender_rep or {})
    rep.pop("google", None)
    tenant.sender_rep = rep
    db.commit()


def _access_token(c: httpx.Client, refresh: str) -> str:
    r = c.post(GOOGLE_TOKEN, data={"grant_type": "refresh_token", "refresh_token": refresh,
                                    "client_id": settings.GOOGLE_POSTMASTER_CLIENT_ID,
                                    "client_secret": settings.GOOGLE_POSTMASTER_CLIENT_SECRET})
    if r.status_code != 200:
        raise ReputationError("Google access was revoked or expired: connect again")
    return r.json()["access_token"]


def _stat(raw: dict) -> dict:
    day = (raw.get("name") or "").rsplit("/", 1)[-1]
    ips = {i.get("reputation"): int(i.get("ipCount") or 0) for i in raw.get("ipReputations") or []
           if i.get("reputation") and i.get("reputation") != "REPUTATION_CATEGORY_UNSPECIFIED"}
    rep = raw.get("domainReputation")
    return {"day": f"{day[:4]}-{day[4:6]}-{day[6:8]}" if len(day) == 8 else day,
            "domain_reputation": None if rep in (None, "REPUTATION_CATEGORY_UNSPECIFIED") else rep,
            "spam_rate": raw.get("userReportedSpamRatio"),
            "spf": raw.get("spfSuccessRatio"), "dkim": raw.get("dkimSuccessRatio"),
            "dmarc": raw.get("dmarcSuccessRatio"), "tls": raw.get("outboundEncryptionRatio"),
            "ip_reputation": ips,
            "delivery_errors": [{"type": e.get("errorType"), "class": e.get("errorClass"),
                                 "ratio": e.get("errorRatio")} for e in raw.get("deliveryErrors") or []][:5]}


def fetch_google(tenant: models.Tenant, transport=None, today: date | None = None) -> dict:
    """{domain: [daily stats, oldest first]} for the domains in Postmaster."""
    refresh = crypto.decrypt(tenant.postmaster_token)
    if not refresh:
        return {}
    today = today or date.today()
    start = today - timedelta(days=DAYS)
    out: dict[str, list] = {}
    with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
        headers = {"Authorization": f"Bearer {_access_token(c, refresh)}"}
        r = c.get(f"{POSTMASTER}/domains", headers=headers, params={"pageSize": 200})
        if r.status_code != 200:
            raise ReputationError(f"Postmaster Tools answered HTTP {r.status_code}")
        names = [d["name"] for d in r.json().get("domains") or [] if d.get("name", "").startswith("domains/")]
        for name in names[:100]:
            params = {"startDate.year": start.year, "startDate.month": start.month, "startDate.day": start.day,
                      "endDate.year": today.year, "endDate.month": today.month, "endDate.day": today.day,
                      "pageSize": 100}
            r = c.get(f"{POSTMASTER}/{name}/trafficStats", headers=headers, params=params)
            if r.status_code != 200:
                continue
            stats = sorted((_stat(s) for s in r.json().get("trafficStats") or []), key=lambda s: s["day"])
            out[name.split("/", 1)[1].lower()] = stats[-DAYS:]
    return out


# ------------------------------------------------------------------ Microsoft SNDS
def set_snds_key(db: Session, tenant: models.Tenant, key: str | None) -> None:
    key = (key or "").strip()
    tenant.snds_key = crypto.encrypt(key) if key else None
    if not key:
        rep = dict(tenant.sender_rep or {})
        rep.pop("snds", None)
        tenant.sender_rep = rep
    db.commit()


def _pct(v: str) -> float | None:
    v = (v or "").strip().rstrip("%").replace("< ", "").replace("<", "")
    try:
        return float(v) / 100
    except ValueError:
        return None


def _int(v: str) -> int:
    try:
        return int((v or "0").strip() or 0)
    except ValueError:
        return 0


def parse_snds(data_csv: str, status_csv: str) -> dict:
    rows = []
    for r in csv.reader(io.StringIO(data_csv)):
        if len(r) < 11 or not r[0].strip() or r[0].strip().lower().startswith("ip"):
            continue
        rows.append({"ip": r[0].strip(), "start": r[1].strip(), "end": r[2].strip(), "recipients": _int(r[5]),
                     "filter": (r[6].strip().upper() or None), "complaint_rate": _pct(r[7]),
                     "trap_hits": _int(r[10]), "helo": r[11].strip()[:100] if len(r) > 11 else None})
    blocked = []
    for r in csv.reader(io.StringIO(status_csv)):
        if len(r) >= 3 and r[0].strip() and not r[0].strip().lower().startswith("first"):
            blocked.append({"first": r[0].strip(), "last": r[1].strip(), "blocked": r[2].strip(),
                            "details": r[3].strip()[:200] if len(r) > 3 else ""})
    return {"rows": rows[-200:], "blocked": blocked[:200]}


def fetch_snds(tenant: models.Tenant, transport=None) -> dict | None:
    key = crypto.decrypt(tenant.snds_key)
    if not key:
        return None
    with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
        d = c.get(SNDS_DATA, params={"key": key})
        s = c.get(SNDS_STATUS, params={"key": key})
    if d.status_code != 200:
        raise ReputationError(f"SNDS answered HTTP {d.status_code}: check the access key")
    return parse_snds(d.text, s.text if s.status_code == 200 else "")


# ------------------------------------------------------------------ problems + refresh
def problems(rep: dict) -> list[dict]:
    """[{key, domain, text}] for what needs attention now."""
    out = []
    for domain, stats in (rep.get("google") or {}).get("domains", {}).items():
        last = next((s for s in reversed(stats) if s.get("domain_reputation") or s.get("spam_rate") is not None), None)
        if not last:
            continue
        if last.get("domain_reputation") in BAD_REPUTATION:
            out.append({"key": f"g-rep:{domain}:{last['domain_reputation']}", "domain": domain,
                        "text": f"Gmail rates {domain}'s reputation {last['domain_reputation']} ({last['day']}): "
                                "more of its mail goes to spam."})
        if (last.get("spam_rate") or 0) >= SPAM_LIMIT:
            out.append({"key": f"g-spam:{domain}", "domain": domain,
                        "text": f"Gmail users reported {last['spam_rate']:.2%} of {domain}'s mail as spam "
                                f"({last['day']}); Gmail's limit for bulk senders is 0.30%."})
    snds = rep.get("snds") or {}
    for row in snds.get("rows") or []:
        if row.get("filter") == "RED":
            out.append({"key": f"s-red:{row['ip']}", "domain": None,
                        "text": f"Outlook.com filtered most mail from {row['ip']} as spam (SNDS: red, "
                                f"{row['start'][:10]})."})
    for b in snds.get("blocked") or []:
        if b.get("blocked", "").lower().startswith("y"):
            ip = b["first"] if b["first"] == b["last"] else f"{b['first']}–{b['last']}"
            out.append({"key": f"s-block:{ip}", "domain": None,
                        "text": f"Outlook.com is blocking mail from {ip}. {b.get('details') or ''}".strip()})
    return out


def refresh(db: Session, tenant: models.Tenant, force: bool = False, transport=None,
            now: datetime | None = None) -> dict:
    """Fetch both sources, store them, and tell the team about new problems."""
    now = now or datetime.utcnow()
    rep = dict(tenant.sender_rep or {})
    last = rep.get("fetched_at")
    if not force and last:
        try:
            if now - datetime.fromisoformat(last.rstrip("Z")) < REFRESH_EVERY:
                return rep
        except ValueError:
            pass
    errors = {}
    if tenant.postmaster_token:
        try:
            rep["google"] = {"domains": fetch_google(tenant, transport), "at": now.isoformat() + "Z"}
        except (ReputationError, httpx.HTTPError, KeyError, ValueError) as exc:
            errors["google"] = str(exc)[:200] if isinstance(exc, ReputationError) else "Google didn't answer"
    if tenant.snds_key:
        try:
            rep["snds"] = {**(fetch_snds(tenant, transport) or {}), "at": now.isoformat() + "Z"}
        except (ReputationError, httpx.HTTPError) as exc:
            errors["snds"] = str(exc)[:200] if isinstance(exc, ReputationError) else "SNDS didn't answer"
    rep["errors"] = errors
    rep["fetched_at"] = now.isoformat() + "Z"
    found = problems(rep)
    seen = set(rep.get("alerted") or [])
    new = [p for p in found if p["key"] not in seen]
    rep["alerted"] = sorted(p["key"] for p in found)  # an issue that clears and comes back alerts again
    tenant.sender_rep = rep
    db.commit()
    if new:
        _alert(db, tenant, new)
    return rep


def _alert(db: Session, tenant: models.Tenant, new: list[dict]) -> None:
    monitors = {m.domain: m for m in db.query(models.Monitor).filter(models.Monitor.tenant_id == tenant.id)}
    for p in new:
        m = monitors.get(p["domain"]) if p["domain"] else None
        if m:
            db.add(models.Alert(tenant_id=tenant.id, monitor_id=m.id, kind="sender_reputation", message=p["text"]))
    db.commit()
    team = mailer.team_recipients(db, tenant.id)
    if team:
        body = "\n".join("- " + p["text"] for p in new)
        mailer.send_email(team, "Mailbox provider reputation warning",
                          f"{body}\n\nDetails: {settings.APP_URL.rstrip('/')}/dashboard#reports\n", tenant=tenant)


def refresh_all(db: Session) -> dict:
    stats = {"checked": 0, "failed": 0}
    rows = db.query(models.Tenant).filter((models.Tenant.postmaster_token.isnot(None))
                                          | (models.Tenant.snds_key.isnot(None))).all()
    for t in rows:
        if (t.status or "active") != "active":
            continue
        try:
            refresh(db, t)
            stats["checked"] += 1
        except Exception:
            db.rollback()
            stats["failed"] += 1
            log.exception("sender reputation refresh failed for tenant %s", t.id)
    return stats


def summary(tenant: models.Tenant) -> dict:
    rep = tenant.sender_rep or {}
    return {"google": {"configured": google_configured(), "connected": bool(tenant.postmaster_token),
                       "account": tenant.postmaster_email,
                       "domains": (rep.get("google") or {}).get("domains", {})},
            "snds": {"connected": bool(tenant.snds_key), "rows": (rep.get("snds") or {}).get("rows", []),
                     "blocked": (rep.get("snds") or {}).get("blocked", [])},
            "fetched_at": rep.get("fetched_at"), "errors": rep.get("errors") or {},
            "problems": [p["text"] for p in problems(rep)]}
