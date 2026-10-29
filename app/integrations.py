"""Alert exports beyond webhooks: a SIEM (syslog RFC 5424 over UDP, TCP or
TLS, or Splunk HTTP Event Collector) and tickets in a PSA (ConnectWise Manage,
HaloPSA, Autotask) or an open-source helpdesk (Zammad, GLPI). Configured per team; secrets are encrypted at rest.

Delivery is best-effort, like webhooks: alerts are stored whatever happens
here, and a failed export never fails a scan. Every destination must be a
public host (https for HTTP APIs), so a team can't point PhishLens at the
server's own network."""
import base64
import html
import ipaddress
import json
import logging
import re
import socket
import ssl
import urllib.parse
from datetime import datetime

import httpx

from . import crypto, webhooks
from .config import settings
from .scanner import net

log = logging.getLogger("phishlens.integrations")
TIMEOUT = 10
ALERT_KINDS = ("score_drop", "check_failed", "dns_changed", "lookalike_registered", "cert_expiring")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

# Secret fields: stored encrypted under "<name>_enc", never returned.
SIEM_SECRETS = {"splunk_hec": ("token",), "syslog": ()}
PSA_SECRETS = {"connectwise": ("private_key",), "halopsa": ("client_secret",), "autotask": ("secret",),
               "zammad": ("token",), "glpi": ("user_token",)}
PSA_NAMES = {"connectwise": "ConnectWise Manage", "halopsa": "HaloPSA", "autotask": "Autotask",
             "zammad": "Zammad", "glpi": "GLPI"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ConfigError(ValueError):
    pass


# ------------------------------------------------------------------ validation
def _dev_ok(host: str) -> bool:
    app_host = urllib.parse.urlparse(settings.APP_URL).hostname or ""
    return webhooks.is_local_dev_host(host) and webhooks.is_local_dev_host(app_host)


def _https_url(url: str, what: str) -> str:
    url = (url or "").strip().rstrip("/")
    parts = urllib.parse.urlparse(url)
    if parts.scheme != "https" or not parts.hostname:
        if not (parts.scheme == "http" and _dev_ok(parts.hostname or "")):
            raise ConfigError(f"{what} must be an https:// URL")
    if not webhooks.url_allowed(url):
        raise ConfigError(f"{what} must be on a public host")
    return url


def _public_address(host: str, port: int) -> tuple:
    """Resolve once and connect to the checked address, so a DNS answer that
    changes between the check and the connection can't reach an internal one."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise ConfigError(f"Can't resolve {host}") from None
    if _dev_ok(host):
        return infos[0][4]
    if not infos or not all(net.is_public_ip(i[4][0]) for i in infos):
        raise ConfigError("SIEM host must resolve to a public address")
    return infos[0][4]


def _int(value, what: str, lo: int = 1, hi: int = 2**31 - 1) -> int | None:
    if value in (None, ""):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{what} must be a number") from None
    if not lo <= n <= hi:
        raise ConfigError(f"{what} is out of range")
    return n


def _text(value, what: str, required: bool = True, max_len: int = 200) -> str:
    value = str(value or "").strip()
    if required and not value:
        raise ConfigError(f"{what} is required")
    if len(value) > max_len:
        raise ConfigError(f"{what} is too long")
    return value


def _opt_str(n: int | None) -> str:
    return "" if n is None else str(n)


def _kinds(value) -> list[str]:
    kinds = [k for k in (value or []) if k in ALERT_KINDS]
    return kinds or list(ALERT_KINDS)


def _keep_secrets(clean: dict, raw: dict, previous: dict | None, names: tuple) -> dict:
    """Encrypt new secrets; a blank field keeps the stored one (the UI never sees it)."""
    for name in names:
        new = str(raw.get(name) or "").strip()
        if new:
            clean[f"{name}_enc"] = crypto.encrypt(new)
        elif previous and previous.get("kind") == clean["kind"] and previous.get(f"{name}_enc"):
            clean[f"{name}_enc"] = previous[f"{name}_enc"]
        else:
            raise ConfigError(f"{name.replace('_', ' ').capitalize()} is required")
    return clean


def clean_siem(raw: dict, previous: dict | None = None) -> dict:
    kind = raw.get("kind")
    if kind == "syslog":
        host = _text(raw.get("host"), "Host", max_len=253)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _HOST_RE.match(host):
                raise ConfigError("Host must be a hostname or IP address") from None
        transport = raw.get("transport") or "tls"
        if transport not in ("udp", "tcp", "tls"):
            raise ConfigError("Transport must be udp, tcp or tls")
        port = _int(raw.get("port"), "Port", 1, 65535) or (6514 if transport == "tls" else 514)
        _public_address(host, port)
        return {"kind": kind, "host": host, "port": port, "transport": transport, "kinds": _kinds(raw.get("kinds"))}
    if kind == "splunk_hec":
        url = _https_url(raw.get("url"), "HEC URL")
        if not urllib.parse.urlparse(url).path:
            url += "/services/collector/event"
        clean = {"kind": kind, "url": url, "index": _text(raw.get("index"), "Index", False, 80),
                 "kinds": _kinds(raw.get("kinds"))}
        return _keep_secrets(clean, raw, previous, SIEM_SECRETS[kind])
    raise ConfigError("Choose syslog or Splunk HEC")


def _companies(value) -> dict:
    """Client label (as set on monitors) -> the PSA's company id."""
    out = {}
    for label, cid in (value or {}).items():
        label, cid = str(label).strip()[:100], str(cid).strip()[:50]
        if label and cid:
            out[label] = cid
    if len(out) > 500:
        raise ConfigError("Too many client mappings (500 max)")
    return out


def clean_psa(raw: dict, previous: dict | None = None) -> dict:
    kind = raw.get("kind")
    base = {"kind": kind, "kinds": _kinds(raw.get("kinds")), "companies": _companies(raw.get("companies"))}
    if kind == "connectwise":
        clean = {**base, "url": _https_url(raw.get("url") or "https://api-na.myconnectwise.net", "Site URL"),
                 "company": _text(raw.get("company"), "Login company id", max_len=60),
                 "public_key": _text(raw.get("public_key"), "Public key", max_len=60),
                 "client_id": _text(raw.get("client_id"), "Client id", max_len=60),
                 "board": _text(raw.get("board"), "Service board", max_len=100),
                 "default_company": _text(raw.get("default_company"), "Default company identifier", max_len=50)}
    elif kind == "halopsa":
        clean = {**base, "url": _https_url(raw.get("url"), "Halo URL"),
                 "client_id": _text(raw.get("client_id"), "Client id", max_len=100),
                 "tenant": _text(raw.get("tenant"), "Tenant", False, 60),
                 "tickettype_id": _int(raw.get("tickettype_id"), "Ticket type id"),
                 "default_company": _opt_str(_int(raw.get("default_company"), "Default client id"))}
    elif kind == "autotask":
        clean = {**base, "url": _https_url(raw.get("url"), "Zone URL"),
                 "username": _text(raw.get("username"), "API user name", max_len=100),
                 "integration_code": _text(raw.get("integration_code"), "Integration code", max_len=100),
                 "default_company": _opt_str(_int(raw.get("default_company"), "Default company id", 0)),
                 "queue_id": _int(raw.get("queue_id"), "Queue id"),
                 "priority": _int(raw.get("priority"), "Priority", 1, 4) or 2}
        if not clean["default_company"]:
            raise ConfigError("Default company id is required")
    elif kind == "zammad":
        # Zammad tickets need a customer: client labels map to customer emails.
        clean = {**base, "url": _https_url(raw.get("url"), "Zammad URL"),
                 "group": _text(raw.get("group") or "Users", "Group", max_len=100),
                 "default_company": _text(raw.get("default_company"), "Default customer email", max_len=200).lower()}
        for email in [clean["default_company"], *clean["companies"].values()]:
            if not _EMAIL_RE.match(email):
                raise ConfigError(f"{email} isn't an email address")
    elif kind == "glpi":
        clean = {**base, "url": _https_url(raw.get("url"), "GLPI URL").removesuffix("/apirest.php"),
                 "default_company": _opt_str(_int(raw.get("default_company"), "Default entity id", 0))}
        if any(not v.isdigit() for v in clean["companies"].values()):
            raise ConfigError("GLPI entity ids are numbers")
        # The app token is optional (GLPI only asks for one if an API client sets it).
        app_token = str(raw.get("app_token") or "").strip()
        if app_token:
            clean["app_token_enc"] = crypto.encrypt(app_token)
        elif previous and previous.get("kind") == "glpi" and previous.get("app_token_enc"):
            clean["app_token_enc"] = previous["app_token_enc"]
    else:
        raise ConfigError("Choose ConnectWise, HaloPSA, Autotask, Zammad or GLPI")
    return _keep_secrets(clean, raw, previous, PSA_SECRETS[kind])


def public_view(cfg: dict | None) -> dict | None:
    """Config as shown to the team: secrets replaced by has_<name>."""
    if not cfg:
        return None
    out = {k: v for k, v in cfg.items() if not k.endswith("_enc")}
    for k in cfg:
        if k.endswith("_enc"):
            out["has_" + k[:-4]] = True
    return out


def _secret(cfg: dict, name: str) -> str:
    value = crypto.decrypt(cfg.get(f"{name}_enc"))
    if not value:
        raise ConfigError("A stored secret can't be read (SECRET_KEY changed?): enter it again")
    return value


# ------------------------------------------------------------------ events
def events_for(monitor, scan, alerts) -> list[dict]:
    return [{"event": "monitor.alert", "domain": monitor.domain, "client": monitor.client, "kind": a.kind,
             "message": a.message, "score": scan.score, "grade": scan.grade,
             "at": (a.created_at or datetime.utcnow()).isoformat() + "Z"} for a in alerts]


def test_event() -> dict:
    return {"event": "integration.test", "domain": "example.com", "client": None, "kind": "test",
            "message": "PhishLens test event: this integration is connected.", "score": None, "grade": None,
            "at": datetime.utcnow().isoformat() + "Z"}


# ------------------------------------------------------------------ SIEM
_SD_ESCAPE = str.maketrans({'"': '\\"', "\\": "\\\\", "]": "\\]"})
_PRI = 16 * 8 + 4  # facility local0, severity warning


def syslog_line(ev: dict) -> bytes:
    """One RFC 5424 message. 32473 is the documentation enterprise number
    (RFC 5612); SIEMs parse the structured data by name either way."""
    host = (urllib.parse.urlparse(settings.APP_URL).hostname or "phishlens")[:255]
    msgid = re.sub(r"[^A-Za-z0-9_.-]", "", ev["kind"])[:32] or "-"
    params = " ".join(f'{k}="{str(ev[k]).translate(_SD_ESCAPE)}"'
                      for k in ("domain", "client", "kind", "score", "grade") if ev.get(k) is not None)
    msg = " ".join(str(ev["message"]).split())[:2000]
    return f"<{_PRI}>1 {ev['at']} {host} phishlens - {msgid} [phishlens@32473 {params}] {msg}".encode()


def send_syslog(cfg: dict, events: list[dict]) -> bool:
    addr = _public_address(cfg["host"], cfg["port"])
    family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
    lines = [syslog_line(ev) for ev in events]
    if cfg["transport"] == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            for line in lines:
                s.sendto(line, addr)
        return True
    with socket.create_connection(addr[:2], timeout=TIMEOUT) as raw:
        sock = raw
        if cfg["transport"] == "tls":
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=cfg["host"])
        # Octet counting (RFC 6587 / RFC 5425): "<length> <message>".
        sock.sendall(b"".join(str(len(line)).encode() + b" " + line for line in lines))
        if sock is not raw:
            sock.close()
    return True


def send_hec(cfg: dict, events: list[dict], client: httpx.Client | None = None) -> bool:
    if not webhooks.url_allowed(cfg["url"]):
        raise ConfigError("HEC URL must be on a public host")
    body = "".join(json.dumps({"event": ev, "sourcetype": "phishlens:alert", "source": "phishlens",
                               **({"index": cfg["index"]} if cfg.get("index") else {}),
                               "time": datetime.fromisoformat(ev["at"].rstrip("Z")).timestamp()})
                   for ev in events)
    client = client or httpx.Client(timeout=TIMEOUT)
    r = client.post(cfg["url"], content=body, headers={"Authorization": f"Splunk {_secret(cfg, 'token')}",
                                                       "Content-Type": "application/json"})
    return 200 <= r.status_code < 300


def send_siem(cfg: dict, events: list[dict]) -> bool:
    events = [e for e in events if e["kind"] == "test" or e["kind"] in cfg.get("kinds", ALERT_KINDS)]
    if not events:
        return False
    if cfg["kind"] == "syslog":
        return send_syslog(cfg, events)
    return send_hec(cfg, events)


# ------------------------------------------------------------------ PSA tickets
def ticket_text(events: list[dict]) -> tuple[str, str]:
    ev = events[0]
    if ev["kind"] == "test":
        return "PhishLens test ticket", ev["message"] + "\nYou can close this ticket."
    title = f"PhishLens: {ev['domain']} email security alert" + (f" ({len(events)})" if len(events) > 1 else "")
    lines = [f"Domain: {ev['domain']}" + (f" (client {ev['client']})" if ev.get("client") else ""),
             f"Score: {ev['score']}/100, grade {ev['grade']}", ""]
    lines += [f"- {e['message']}" for e in events]
    lines += ["", f"Fixes and the full report: {settings.APP_URL.rstrip('/')}/dashboard"]
    return title, "\n".join(lines)


def _company(cfg: dict, client_label: str | None) -> str:
    return cfg.get("companies", {}).get(client_label or "", "") or cfg.get("default_company", "")


def _connectwise(cfg, title, body, company, http) -> str:
    auth = base64.b64encode(f"{cfg['company']}+{cfg['public_key']}:{_secret(cfg, 'private_key')}".encode()).decode()
    payload = {"summary": title[:100], "initialDescription": body, "board": {"name": cfg["board"]}}
    if company:
        payload["company"] = {"identifier": company}
    r = http.post(f"{cfg['url']}/v4_6_release/apis/3.0/service/tickets", json=payload,
                  headers={"Authorization": f"Basic {auth}", "clientId": cfg["client_id"]})
    r.raise_for_status()
    return str(r.json().get("id"))


def _halopsa(cfg, title, body, company, http) -> str:
    token_url = f"{cfg['url']}/auth/token" + (f"?tenant={urllib.parse.quote(cfg['tenant'])}" if cfg.get("tenant") else "")
    tok = http.post(token_url, data={"grant_type": "client_credentials", "client_id": cfg["client_id"],
                                     "client_secret": _secret(cfg, "client_secret"), "scope": "all"})
    tok.raise_for_status()
    ticket = {"summary": title[:250], "details": body}
    if cfg.get("tickettype_id"):
        ticket["tickettype_id"] = cfg["tickettype_id"]
    if company:
        ticket["client_id"] = int(company)
    r = http.post(f"{cfg['url']}/api/tickets", json=[ticket],
                  headers={"Authorization": f"Bearer {tok.json()['access_token']}"})
    r.raise_for_status()
    data = r.json()
    return str((data[0] if isinstance(data, list) else data).get("id"))


def _autotask(cfg, title, body, company, http) -> str:
    payload = {"companyID": int(company), "title": title[:255], "description": body[:8000],
               "status": 1, "priority": cfg.get("priority") or 2}
    if cfg.get("queue_id"):
        payload["queueID"] = cfg["queue_id"]
    r = http.post(f"{cfg['url']}/ATServicesRest/V1.0/Tickets", json=payload,
                  headers={"ApiIntegrationCode": cfg["integration_code"], "UserName": cfg["username"],
                           "Secret": _secret(cfg, "secret")})
    r.raise_for_status()
    return str(r.json().get("itemId"))


def _zammad(cfg, title, body, company, http) -> str:
    # "guess:<email>" finds the customer by email, or creates them.
    payload = {"title": title[:250], "group": cfg["group"], "customer_id": f"guess:{company}",
               "article": {"subject": title[:250], "body": body, "type": "note", "internal": False,
                           "content_type": "text/plain"}}
    r = http.post(f"{cfg['url']}/api/v1/tickets", json=payload,
                  headers={"Authorization": f"Token token={_secret(cfg, 'token')}"})
    r.raise_for_status()
    return str(r.json().get("number") or r.json().get("id"))


def _glpi(cfg, title, body, company, http) -> str:
    api = f"{cfg['url']}/apirest.php"
    headers = {"App-Token": crypto.decrypt(cfg["app_token_enc"])} if cfg.get("app_token_enc") else {}
    s = http.get(f"{api}/initSession", headers={**headers, "Authorization": f"user_token {_secret(cfg, 'user_token')}"})
    s.raise_for_status()
    headers["Session-Token"] = s.json()["session_token"]
    try:
        # GLPI shows the description as rich text: one paragraph per line.
        content = "".join(f"<p>{html.escape(line)}</p>" for line in body.split("\n"))
        ticket = {"name": title[:255], "content": content, "type": 1}  # 1 = incident
        if company:
            ticket["entities_id"] = int(company)
        r = http.post(f"{api}/Ticket", json={"input": ticket}, headers=headers)
        r.raise_for_status()
        return str(r.json().get("id"))
    finally:
        try:
            http.get(f"{api}/killSession", headers=headers)
        except httpx.HTTPError:
            pass


_PSA = {"connectwise": _connectwise, "halopsa": _halopsa, "autotask": _autotask, "zammad": _zammad, "glpi": _glpi}


def create_ticket(cfg: dict, events: list[dict], http: httpx.Client | None = None) -> str | None:
    """Open one ticket for a batch of alerts on one domain. Returns its id."""
    events = [e for e in events if e["kind"] == "test" or e["kind"] in cfg.get("kinds", ALERT_KINDS)]
    if not events:
        return None
    if not webhooks.url_allowed(cfg["url"]):
        raise ConfigError("PSA URL must be on a public host")
    title, body = ticket_text(events)
    company = _company(cfg, events[0].get("client"))
    # No redirects: a 3xx could bounce the credentials somewhere else.
    with (http or httpx.Client(timeout=TIMEOUT, follow_redirects=False)) as client:
        return _PSA[cfg["kind"]](cfg, title, body, company, client)


# ------------------------------------------------------------------ dispatch
def notify_alerts(db, monitor, scan, alerts) -> dict:
    from . import models
    tenant = db.query(models.Tenant).filter(models.Tenant.id == monitor.tenant_id).first()
    out = {"siem": None, "psa": None}
    if not tenant or not alerts:
        return out
    events = events_for(monitor, scan, alerts)
    if tenant.siem:
        try:
            out["siem"] = send_siem(tenant.siem, events)
        except Exception as exc:
            log.warning("SIEM export for %s failed: %s", monitor.domain, exc)
            out["siem"] = False
    if tenant.psa:
        try:
            out["psa"] = create_ticket(tenant.psa, events)
        except Exception as exc:
            log.warning("PSA ticket for %s failed: %s", monitor.domain, exc)
            out["psa"] = False
    return out
