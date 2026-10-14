"""Signed alert webhooks for SIEM ingestion. Best-effort delivery — alerts are
stored in the database regardless; a failed webhook never breaks a scan."""
import hashlib
import hmac
import json
import logging
import urllib.parse
import urllib.request

log = logging.getLogger("phishlens.webhooks")


def is_local_dev_host(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def url_allowed(url: str) -> bool:
    """https to a public host; plain http only to localhost, and only while the
    app itself runs on a local http URL (development)."""
    from .config import settings
    from .scanner import net

    parts = urllib.parse.urlparse(url)
    host = parts.hostname or ""
    if is_local_dev_host(host):
        app_host = urllib.parse.urlparse(settings.APP_URL).hostname or ""
        return is_local_dev_host(app_host)
    return parts.scheme == "https" and net.is_public_host(host)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could bounce the signed POST to an internal address."""
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def deliver(url: str, secret: str, event: dict) -> bool:
    if not url_allowed(url):
        log.warning("webhook delivery to %s refused: not a public https URL", url)
        return False
    body = json.dumps(event, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-PhishLens-Event": event.get("event", ""),
            "X-PhishLens-Signature": "sha256=" + sig,
            "User-Agent": "PhishLens-webhook/1.0",
        },
    )
    try:
        with _opener.open(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        log.warning("webhook delivery to %s failed: %s", url, exc)
        return False


def notify_alerts(db, monitor, scan, alerts) -> bool:
    """POST monitor alerts to the tenant's webhook URL, HMAC-signed."""
    from . import models
    tenant = db.query(models.Tenant).filter(models.Tenant.id == monitor.tenant_id).first()
    if not tenant or not tenant.webhook_url or not tenant.webhook_secret:
        return False
    event = {
        "event": "monitor.alert",
        "domain": monitor.domain,
        "score": scan.score,
        "grade": scan.grade,
        "alerts": [{"kind": a.kind, "message": a.message,
                    "at": a.created_at.isoformat() + "Z"} for a in alerts],
        "checked_at": scan.created_at.isoformat() + "Z" if scan.created_at else None,
    }
    return deliver(tenant.webhook_url, tenant.webhook_secret, event)
