"""Microsoft 365 and Google Workspace security check (read-only).

The checks that decide whether a phished password turns into a breach:
multi-factor sign-in, legacy sign-in, how many people are global admins,
whether users can grant apps access to their mail (consent phishing), and
mailboxes that forward mail to outside addresses (a classic sign of a
compromised account).

- Microsoft 365: the customer's admin grants admin consent to the server's
  multi-tenant app (read-only application permissions). PhishLens stores only
  the customer's directory (tenant) id and gets short-lived tokens with
  client credentials.
- Google Workspace: the customer's super admin authorizes the server's
  service account client id for domain-wide delegation with read-only
  directory scopes plus gmail.settings.basic (to read forwarding settings;
  no access to mail content).

Results use the scanner's check shape: {key, name, status, details, issues, fixes}.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta

import httpx
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import models
from .config import settings

log = logging.getLogger("phishlens.posture")

GRAPH = "https://graph.microsoft.com/v1.0"
MS_LOGIN = "https://login.microsoftonline.com"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_DIR = "https://admin.googleapis.com/admin/directory/v1"
GMAIL = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_SCOPES = ("https://www.googleapis.com/auth/admin.directory.user.readonly",
                 "https://www.googleapis.com/auth/admin.directory.domain.readonly")
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
MAX_USERS = 100
TIMEOUT = 20
STATE_TTL = 900
RECHECK_EVERY = timedelta(days=7)
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class PostureError(Exception):
    pass


def _check(key, name, status, details, issues=(), fixes=()):
    return {"key": key, "name": name, "status": status, "details": details,
            "issues": list(issues), "fixes": list(fixes)}


def _external(address: str, own: set[str]) -> bool:
    dom = (address or "").rsplit("@", 1)[-1].lower().strip(">")
    return bool(dom) and not any(dom == d or dom.endswith("." + d) for d in own)


# ------------------------------------------------------------------ Microsoft 365
def m365_configured() -> bool:
    return bool(settings.M365_CLIENT_ID and settings.M365_CLIENT_SECRET)


def m365_redirect() -> str:
    return settings.APP_URL.rstrip("/") + "/posture/m365/callback"


def _state(tenant: models.Tenant, user: models.User, kind: str) -> tuple[str, str]:
    state = secrets.token_urlsafe(24)
    cookie = jwt.encode({"tid": tenant.id, "uid": user.id, "state": state, "kind": kind,
                         "exp": int(time.time()) + STATE_TTL, "typ": "posture_state"},
                        settings.SECRET_KEY, algorithm="HS256")
    return state, cookie


def read_state(cookie: str | None) -> dict:
    try:
        data = jwt.decode(cookie or "", settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as exc:
        raise PostureError("The consent took too long: start again") from exc
    if data.get("typ") != "posture_state":
        raise PostureError("Invalid state")
    return data


def m365_start(tenant: models.Tenant, user: models.User) -> tuple[str, str]:
    if not m365_configured():
        raise PostureError("The Microsoft 365 check isn't set up on this server (M365_CLIENT_ID)")
    state, cookie = _state(tenant, user, "m365")
    params = {"client_id": settings.M365_CLIENT_ID, "redirect_uri": m365_redirect(), "state": state}
    return f"{MS_LOGIN}/organizations/adminconsent?" + urllib.parse.urlencode(params), cookie


def m365_connect(db: Session, tenant: models.Tenant, directory_id: str) -> None:
    directory_id = (directory_id or "").lower()
    if not GUID.match(directory_id):
        raise PostureError("Microsoft didn't return a valid directory id")
    tenant.posture = {**(tenant.posture or {}), "m365": {"directory": directory_id,
                                                         "connected_at": datetime.utcnow().isoformat() + "Z"}}
    db.commit()


def _m365_token(c: httpx.Client, directory: str) -> str:
    r = c.post(f"{MS_LOGIN}/{directory}/oauth2/v2.0/token", data={
        "client_id": settings.M365_CLIENT_ID, "client_secret": settings.M365_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
    if r.status_code != 200:
        raise PostureError("Microsoft refused access: the admin consent may have been removed. Connect again.")
    return r.json()["access_token"]


def _get(c: httpx.Client, url: str, headers: dict, params: dict | None = None) -> dict | None:
    r = c.get(url, headers=headers, params=params)
    if r.status_code in (401, 403, 404):
        return None
    r.raise_for_status()
    return r.json()


def m365_checks(directory: str, transport=None) -> dict:
    with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
        h = {"Authorization": f"Bearer {_m365_token(c, directory)}"}
        org = _get(c, f"{GRAPH}/organization", h) or {}
        domains = [d for d in (_get(c, f"{GRAPH}/domains", h) or {}).get("value", []) if d.get("isVerified")]
        own = {d["id"].lower() for d in domains}
        sd = _get(c, f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", h)
        ca = _get(c, f"{GRAPH}/identity/conditionalAccess/policies", h)
        auth = _get(c, f"{GRAPH}/policies/authorizationPolicy", h)
        roles = _get(c, f"{GRAPH}/directoryRoles", h, {"$filter": f"roleTemplateId eq '{GLOBAL_ADMIN}'"})
        admins = None
        if roles and roles.get("value"):
            m = _get(c, f"{GRAPH}/directoryRoles/{roles['value'][0]['id']}/members", h,
                     {"$select": "id,userPrincipalName"})
            admins = [x.get("userPrincipalName") or x.get("id") for x in (m or {}).get("value", [])]
        reg = _get(c, f"{GRAPH}/reports/authenticationMethods/userRegistrationDetails", h,
                    {"$select": "userPrincipalName,isMfaRegistered,userType", "$top": 999})
        users = (_get(c, f"{GRAPH}/users", h, {"$select": "id,userPrincipalName,accountEnabled,userType",
                                                "$top": MAX_USERS}) or {}).get("value", [])
        forwards, rules_read = [], 0
        for u in [u for u in users if u.get("accountEnabled") and u.get("userType") != "Guest"][:MAX_USERS]:
            rules = _get(c, f"{GRAPH}/users/{u['id']}/mailFolders/inbox/messageRules", h)
            if rules is None:
                continue
            rules_read += 1
            for rule in rules.get("value", []):
                acts = rule.get("actions") or {}
                targets = [t.get("emailAddress", {}).get("address", "") for k in ("forwardTo", "redirectTo",
                           "forwardAsAttachmentTo") for t in acts.get(k) or []]
                ext = [t for t in targets if _external(t, own)]
                if ext and rule.get("isEnabled", True):
                    forwards.append(f"{u['userPrincipalName']} → {', '.join(ext)} (rule “{rule.get('displayName', '')}”)")
    checks = []
    # Multi-factor sign-in
    sd_on = bool(sd and sd.get("isEnabled"))
    mfa_policies = [p for p in (ca or {}).get("value", []) if p.get("state") == "enabled"
                    and "mfa" in ((p.get("grantControls") or {}).get("builtInControls") or [])
                    and "All" in (((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or [])]
    if sd_on:
        checks.append(_check("m365_mfa", "Multi-factor sign-in", "pass", "Security defaults are on: everyone must use MFA."))
    elif mfa_policies:
        checks.append(_check("m365_mfa", "Multi-factor sign-in", "pass",
                             f"Conditional Access requires MFA for all users ({mfa_policies[0].get('displayName')})."))
    else:
        checks.append(_check("m365_mfa", "Multi-factor sign-in", "fail", "No policy makes everyone use MFA.",
                             ["A stolen password is enough to get into a mailbox."],
                             ["Turn on security defaults (Entra admin center → Overview → Properties → Manage "
                              "security defaults), or add a Conditional Access policy requiring MFA for all users."]))
    if reg and reg.get("value"):
        members = [r for r in reg["value"] if r.get("userType") != "guest"]
        done = sum(1 for r in members if r.get("isMfaRegistered"))
        pct = round(100 * done / len(members)) if members else 100
        missing = [r["userPrincipalName"] for r in members if not r.get("isMfaRegistered")][:10]
        checks.append(_check("m365_mfa_registered", "Users with MFA set up", "pass" if pct >= 95 else "warn" if pct >= 75
                             else "fail", f"{done} of {len(members)} users ({pct}%) have an MFA method registered.",
                             [f"Not registered: {', '.join(missing)}"] if missing else [],
                             ["Ask these users to register at https://aka.ms/mfasetup."] if missing else []))
    # Legacy sign-in (no MFA possible)
    legacy_block = sd_on or any(p.get("state") == "enabled" and "block" in ((p.get("grantControls") or {}).get(
        "builtInControls") or []) and {"exchangeActiveSync", "other"} & set(((p.get("conditions") or {}).get(
            "clientAppTypes") or [])) for p in (ca or {}).get("value", []))
    checks.append(_check("m365_legacy", "Legacy sign-in blocked", "pass" if legacy_block else "warn",
                         "Old mail protocols that skip MFA are blocked." if legacy_block else
                         "No policy blocks legacy sign-in (IMAP, POP, basic SMTP).",
                         [] if legacy_block else ["Password-spraying attacks use legacy protocols, which skip MFA."],
                         [] if legacy_block else ["Add a Conditional Access policy that blocks 'Exchange ActiveSync' and "
                                                  "'Other clients', or turn on security defaults."]))
    if admins is not None:
        n = len(admins)
        status = "pass" if 2 <= n <= 4 else "warn"
        checks.append(_check("m365_admins", "Global administrators", status,
                             f"{n} global administrator{'s' if n != 1 else ''}: {', '.join(admins[:6])}",
                             [] if status == "pass" else ["Microsoft recommends 2 to 4: fewer risks lock-out, more "
                                                          "means more accounts that can take over everything."],
                             [] if status == "pass" else ["Use less powerful roles (Exchange, User, Helpdesk admin) "
                                                          "for day-to-day work."]))
    if auth:
        grants = ((auth.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or [])
        risky = any(g.endswith("microsoft-user-default-legacy") for g in grants)
        checks.append(_check("m365_consent", "Users can't hand apps access to their mail", "fail" if risky else "pass",
                             "Users can consent to any app reading their mail and files." if risky
                             else "User consent to apps is limited or off.",
                             ["Consent phishing: a fake app asks for access and keeps it even after a password reset."]
                             if risky else [],
                             ["Entra admin center → Enterprise apps → Consent and permissions → allow user consent "
                              "only for verified publishers, or turn it off and use the admin consent workflow."]
                             if risky else []))
    if rules_read:
        checks.append(_check("m365_forwarding", "Mail forwarded outside the company", "fail" if forwards else "pass",
                             f"{len(forwards)} inbox rule{'s' if len(forwards) != 1 else ''} forward mail outside "
                             f"(checked {rules_read} mailboxes)." if forwards else
                             f"No inbox rule forwards mail outside (checked {rules_read} mailboxes).",
                             forwards[:20], ["Check each rule with its owner; attackers add these after taking over a "
                                             "mailbox. Also block automatic external forwarding in the Defender "
                                             "outbound spam policy."] if forwards else []))
    return {"provider": "m365", "organization": ((org.get("value") or [{}])[0]).get("displayName"),
            "domains": sorted(own), "checks": checks, "checked_at": datetime.utcnow().isoformat() + "Z"}


# ------------------------------------------------------------------ Google Workspace
def _service_account() -> dict | None:
    raw = settings.GOOGLE_WORKSPACE_SERVICE_ACCOUNT
    if not raw:
        return None
    try:
        if raw.strip().startswith("{"):
            return json.loads(raw)
        with open(raw, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        log.error("GOOGLE_WORKSPACE_SERVICE_ACCOUNT is not valid JSON or a readable file")
        return None


def gws_configured() -> bool:
    return _service_account() is not None


def gws_client_id() -> str | None:
    sa = _service_account()
    return str(sa.get("client_id")) if sa else None


def gws_scopes() -> list[str]:
    return [*GOOGLE_SCOPES, GMAIL_SCOPE]


def gws_connect(db: Session, tenant: models.Tenant, domain: str, admin_email: str) -> None:
    domain = domain.strip().lower()
    admin_email = admin_email.strip().lower()
    if not admin_email.endswith("@" + domain):
        raise PostureError("The admin's address must be in the Workspace domain")
    tenant.posture = {**(tenant.posture or {}), "gws": {"domain": domain, "admin": admin_email,
                                                        "connected_at": datetime.utcnow().isoformat() + "Z"}}
    db.commit()


def _google_token(c: httpx.Client, sa: dict, subject: str, scopes) -> str | None:
    now = int(time.time())
    assertion = jwt.encode({"iss": sa["client_email"], "sub": subject, "scope": " ".join(scopes),
                            "aud": GOOGLE_TOKEN, "iat": now, "exp": now + 600},
                           sa["private_key"], algorithm="RS256")
    r = c.post(GOOGLE_TOKEN, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
    return r.json().get("access_token") if r.status_code == 200 else None


def gws_checks(domain: str, admin: str, transport=None) -> dict:
    sa = _service_account()
    if not sa:
        raise PostureError("The Google Workspace check isn't set up on this server")
    with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
        token = _google_token(c, sa, admin, GOOGLE_SCOPES)
        if not token:
            raise PostureError("Google refused access: authorize the client id for domain-wide delegation "
                               "with the listed scopes, and check the admin address")
        h = {"Authorization": f"Bearer {token}"}
        doms = (_get(c, f"{GOOGLE_DIR}/customer/my_customer/domains", h) or {}).get("domains", [])
        own = {d["domainName"].lower() for d in doms if d.get("verified")} or {domain}
        users = (_get(c, f"{GOOGLE_DIR}/users", h, {"customer": "my_customer", "maxResults": 500,
                                                    "query": "isSuspended=false"}) or {}).get("users", [])
        forwards, read = [], 0
        for u in users[:MAX_USERS]:
            email = u.get("primaryEmail")
            t = _google_token(c, sa, email, [GMAIL_SCOPE]) if email else None
            if not t:
                continue
            fwd = _get(c, f"{GMAIL}/users/me/settings/autoForwarding", {"Authorization": f"Bearer {t}"})
            if fwd is None:
                continue
            read += 1
            if fwd.get("enabled") and _external(fwd.get("emailAddress", ""), own):
                forwards.append(f"{email} → {fwd['emailAddress']}")
    checks = []
    if users:
        enrolled = [u for u in users if u.get("isEnrolledIn2Sv")]
        enforced = all(u.get("isEnforcedIn2Sv") for u in users)
        pct = round(100 * len(enrolled) / len(users))
        missing = [u["primaryEmail"] for u in users if not u.get("isEnrolledIn2Sv")][:10]
        checks.append(_check("gws_2sv", "2-Step Verification", "pass" if enforced and pct == 100 else
                             "warn" if pct >= 75 else "fail",
                             f"{len(enrolled)} of {len(users)} users ({pct}%) use 2-Step Verification; "
                             f"{'enforced for everyone' if enforced else 'not enforced for everyone'}.",
                             [f"Not enrolled: {', '.join(missing)}"] if missing else [],
                             [] if enforced and pct == 100 else ["Admin console → Security → Authentication → "
                                                                 "2-step verification → Enforcement: On."]))
        admins = [u["primaryEmail"] for u in users if u.get("isAdmin")]
        status = "pass" if 2 <= len(admins) <= 4 else "warn"
        checks.append(_check("gws_admins", "Super administrators", status,
                             f"{len(admins)} super admin{'s' if len(admins) != 1 else ''}: {', '.join(admins[:6])}",
                             [] if status == "pass" else ["Google recommends a small number (2–4) of super admins."],
                             [] if status == "pass" else ["Give day-to-day admins a more limited admin role."]))
        weak = [u["primaryEmail"] for u in users if u.get("isAdmin") and not u.get("isEnrolledIn2Sv")]
        if weak:
            checks.append(_check("gws_admin_2sv", "Super admins without 2-Step Verification", "fail",
                                 f"{len(weak)} super admin{'s' if len(weak) != 1 else ''} without 2SV.", weak,
                                 ["Turn on 2SV (ideally a security key) for every super admin now."]))
    if read:
        checks.append(_check("gws_forwarding", "Mail forwarded outside the company", "fail" if forwards else "pass",
                             f"{len(forwards)} mailbox{'es' if len(forwards) != 1 else ''} forward mail outside "
                             f"(checked {read})." if forwards else f"No mailbox forwards mail outside (checked {read}).",
                             forwards[:20], ["Check each with its owner, and turn off automatic forwarding in "
                                             "Admin console → Apps → Gmail → End user access."] if forwards else []))
    return {"provider": "gws", "organization": domain, "domains": sorted(own), "checks": checks,
            "checked_at": datetime.utcnow().isoformat() + "Z"}


# ------------------------------------------------------------------ run + store
def run(db: Session, tenant: models.Tenant, transport=None) -> dict:
    """Run the connected checks; store results (or errors) in tenant.posture."""
    posture = dict(tenant.posture or {})
    for kind, fn in (("m365", lambda p: m365_checks(p["directory"], transport)),
                     ("gws", lambda p: gws_checks(p["domain"], p["admin"], transport))):
        conf = posture.get(kind)
        if not conf:
            continue
        try:
            conf = {**conf, "result": fn(conf), "error": None}
        except PostureError as exc:
            conf = {**conf, "error": str(exc)}
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("posture %s failed: %s", kind, exc)
            conf = {**conf, "error": "The provider didn't answer; will try again"}
        posture[kind] = conf
    posture["checked_at"] = datetime.utcnow().isoformat() + "Z"
    tenant.posture = posture
    db.commit()
    return posture


def run_all(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    stats = {"checked": 0}
    for t in db.query(models.Tenant).filter(models.Tenant.posture.isnot(None)).all():
        p = t.posture or {}
        if not (p.get("m365") or p.get("gws")) or (t.status or "active") != "active":
            continue
        last = p.get("checked_at")
        try:
            if last and now - datetime.fromisoformat(last.rstrip("Z")) < RECHECK_EVERY:
                continue
        except ValueError:
            pass
        try:
            run(db, t)
            stats["checked"] += 1
        except Exception:
            db.rollback()
            log.exception("posture check failed for tenant %s", t.id)
    return stats


def summary(tenant: models.Tenant) -> dict:
    p = tenant.posture or {}
    out = {"m365": {"configured": m365_configured(), "connected": bool(p.get("m365"))},
           "gws": {"configured": gws_configured(), "connected": bool(p.get("gws")), "client_id": gws_client_id(),
                   "scopes": gws_scopes()},
           "checked_at": p.get("checked_at")}
    for k in ("m365", "gws"):
        conf = p.get(k) or {}
        out[k].update({"result": conf.get("result"), "error": conf.get("error"),
                       "domain": conf.get("domain"), "admin": conf.get("admin")})
    return out
