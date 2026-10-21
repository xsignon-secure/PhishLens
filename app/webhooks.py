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


def chat_kind(url: str) -> str | None:
    """'slack' / 'teams' for chat incoming-webhook URLs, which take a message
    payload instead of the raw event; None for a generic (SIEM) endpoint."""
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host == "hooks.slack.com":
        return "slack"
    if host.endswith(".webhook.office.com") or host.endswith(".logic.azure.com") \
            or host.endswith(".powerplatform.com"):
        return "teams"
    if host in ("discord.com", "discordapp.com"):
        return "discord"
    return None


def chat_text(event: dict) -> str:
    from .config import settings

    if event.get("event") == "webhook.test":
        return "PhishLens test alert: your webhook is connected."
    lines = [f"PhishLens alert for {event.get('domain')} "
             f"(score {event.get('score')}, grade {event.get('grade')})"]
    lines += [f"- {a.get('message')}" for a in event.get("alerts", [])]
    lines.append(f"{settings.APP_URL}/dashboard")
    return "\n".join(lines)


def deliver(url: str, secret: str, event: dict) -> bool:
    if not url_allowed(url):
        log.warning("webhook delivery to %s refused: not a public https URL", url)
        return False
    kind = chat_kind(url)
    if kind == "discord":
        payload = {"content": chat_text(event)}
    elif kind == "teams":
        # Adaptive Card: accepted by both classic Teams incoming webhooks and
        # the Workflows "post to a channel when a webhook request is received".
        payload = {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"type": "AdaptiveCard", "version": "1.4",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "body": [{"type": "TextBlock", "wrap": True, "text": chat_text(event)}]},
        }]}
    elif kind == "slack":
        payload = {"text": chat_text(event)}
    else:
        payload = event
    body = json.dumps(payload, separators=(",", ":")).encode()
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
