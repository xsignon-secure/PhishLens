"""Outbound email alerts. stdlib smtplib only — no dependencies, no AI.

Deliberately boring: plain-text emails, sent through the company's own mail
server (Dashboard → Email server) or else the server-wide SMTP_* settings.
If email is unconfigured or fails, scanning and alerts keep working — the
alert rows in the database are the source of truth, email is a courtesy copy.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from . import models
from .config import settings

log = logging.getLogger("phishlens.mailer")


SMTP_PORTS = (25, 465, 587, 2525)
SECURITY_MODES = ("starttls", "ssl")


class SmtpError(Exception):
    pass


def is_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


def real_email(email: str | None) -> bool:
    return bool(email) and "@" in email and not email.endswith(".invalid")


def server_config() -> dict | None:
    """The server-wide mail settings (SMTP_*), used when a company has not
    connected its own mail server."""
    if not is_configured():
        return None
    return {"host": settings.SMTP_HOST, "port": settings.SMTP_PORT, "username": settings.SMTP_USER,
            "password": settings.SMTP_PASSWORD, "from_address": settings.SMTP_FROM, "from_name": None,
            "security": "starttls" if settings.SMTP_USE_TLS else "ssl", "pinned": False}


def tenant_config(tenant: "models.Tenant | None") -> dict | None:
    """A company's own mail server, password decrypted, or None."""
    from . import crypto
    c = (tenant.smtp if tenant else None) or {}
    if not c.get("host") or not c.get("from_address"):
        return None
    return {**c, "password": crypto.decrypt(c.get("password")) if c.get("password") else "", "pinned": True}


def config_for(tenant: "models.Tenant | None") -> dict | None:
    return tenant_config(tenant) or server_config()


def _public_ip(host: str) -> str:
    """Company mail servers are typed in by users: only connect to a public
    address, resolved once and pinned for the connection (no DNS rebinding
    onto internal services)."""
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise SmtpError(f"Mail server {host} does not resolve")
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise SmtpError("The mail server must be on a public address")
    return infos[0][4][0]


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, ip: str, **kw):
        self._pinned_ip = ip
        super().__init__(**kw)

    def _get_socket(self, host, port, timeout):
        import socket
        return socket.create_connection((self._pinned_ip, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, ip: str, **kw):
        self._pinned_ip = ip
        super().__init__(**kw)

    def _get_socket(self, host, port, timeout):
        import socket
        sock = socket.create_connection((self._pinned_ip, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._host)


def deliver(cfg: dict, msg: EmailMessage) -> None:
    """Hand a message to a mail server. Raises SmtpError with the server's
    answer, for the admin's "test" button and delivery status."""
    server = None
    context = ssl.create_default_context()
    host, port = cfg["host"], int(cfg.get("port") or 587)
    try:
        ip = _public_ip(host) if cfg.get("pinned") else None
        if cfg.get("security") == "ssl":
            server = (_PinnedSMTPSSL(ip, context=context, timeout=20) if ip
                      else smtplib.SMTP_SSL(context=context, timeout=20))
        else:
            server = _PinnedSMTP(ip, timeout=20) if ip else smtplib.SMTP(timeout=20)
        server.connect(host, port)
        if cfg.get("security") != "ssl":
            server.starttls(context=context)  # never send a password in clear text
        if cfg.get("username"):
            server.login(cfg["username"], cfg.get("password") or "")
        server.send_message(msg)
    except SmtpError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise SmtpError("The mail server refused the username or password")
    except smtplib.SMTPNotSupportedError:
        raise SmtpError("The mail server doesn't support STARTTLS: choose SSL/TLS (usually port 465)")
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise SmtpError(f"Could not send: {str(exc)[:200]}")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def build_message(cfg: dict, to: list[str], subject: str, body: str,
                  attachments: list[tuple[str, bytes, str]] | None = None, *, prefix: bool = True) -> EmailMessage:
    from email.utils import formataddr
    msg = EmailMessage()
    msg["Subject"] = f"[{settings.APP_NAME}] {subject}" if prefix else subject
    msg["From"] = formataddr((cfg["from_name"], cfg["from_address"])) if cfg.get("from_name") else cfg["from_address"]
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg


def send_email(to: list[str], subject: str, body: str,
               attachments: list[tuple[str, bytes, str]] | None = None,
               tenant: "models.Tenant | None" = None) -> bool:
    """Send a plain-text email, with optional (filename, bytes, mime type)
    attachments, through the company's own mail server when it has one.
    Returns True if handed to a mail server; never raises."""
    cfg = config_for(tenant)
    if not to or not cfg:
        return False
    try:
        deliver(cfg, build_message(cfg, to, subject, body, attachments))
        return True
    except SmtpError as exc:  # email must never break a scan
        log.warning("email send failed: %s", exc)
        return False


def team_recipients(db, tenant_id: str) -> list[str]:
    """Owners and admins of a company: alert and report emails go to them."""
    rows = (db.query(models.User.email)
            .filter(models.User.tenant_id == tenant_id, models.User.role.in_(("owner", "admin")),
                    models.User.is_active.is_(True), models.User.status == "active").all())
    return [e for (e,) in rows if real_email(e)]


def notify_monitor_alerts(db, monitor: "models.Monitor", scan: "models.Scan",
                          alerts: list["models.Alert"], prev_score: int | None) -> bool:
    """Email the company's owners and admins (and any extra recipients) about
    new monitor alerts. Returns True if sent."""
    recipients = team_recipients(db, monitor.tenant_id)
    tenant = db.query(models.Tenant).filter(models.Tenant.id == monitor.tenant_id).first()
    # Extra recipients, e.g. an MSP's PSA email-to-ticket inbox.
    recipients += [e for e in (tenant.alert_emails or []) if e not in recipients] if tenant else []
    if not recipients:
        return False
    from .branding import for_tenant
    brand = for_tenant(tenant) or {}
    name = brand.get("name") or settings.APP_NAME
    lines = [
        f"{name} monitor alert",
        "",
        f"Domain:  {monitor.domain}",
        f"Score:   {prev_score} -> {scan.score} ({scan.grade})",
        f"Checked: {scan.created_at.isoformat() + 'Z' if scan.created_at else 'just now'}",
        "",
        "Alerts:",
    ]
    for alert in alerts:
        lines.append(f"- {alert.kind}: {alert.message}")
    lines += [
        "",
        f"Details: {settings.APP_URL}/dashboard",
        *([brand["footer"]] if brand.get("footer") else []),
        "",
        "Remove the monitor in your dashboard to stop these alerts.",
    ]
    client = f"[{monitor.client}] " if monitor.client else ""
    return send_email(recipients, f"{client}{monitor.domain} security alert", "\n".join(lines), tenant=tenant)
