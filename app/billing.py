"""Stripe subscriptions, called over Stripe's REST API with httpx (no SDK).

Flow: owner clicks Upgrade -> Checkout Session -> Stripe redirects back ->
Stripe's webhook (signed) flips the tenant to "pro". The webhook is the only
thing that changes the plan: the redirect alone proves nothing.
"""
import hashlib
import hmac
import time

import httpx

from .config import settings

API = "https://api.stripe.com/v1"
ACTIVE = {"active", "trialing", "past_due"}  # past_due: Stripe is still retrying
SIGNATURE_TOLERANCE = 300

# Plan limits. Pro features are only enforced when billing is configured, so
# a self-hosted install without Stripe has everything unlocked.
FREE_MONITORS = 3
PRO_MONITORS = 100


class BillingError(Exception):
    pass


def configured() -> bool:
    return bool(settings.STRIPE_SECRET_KEY and settings.STRIPE_PRICE_ID)


def is_pro(tenant) -> bool:
    return not configured() or tenant.plan == "pro"


def monitor_limit(tenant) -> int:
    return PRO_MONITORS if tenant.plan == "pro" else FREE_MONITORS


def _post(path: str, data: dict) -> dict:
    try:
        r = httpx.post(f"{API}{path}", data=data, timeout=15,
                       auth=(settings.STRIPE_SECRET_KEY, ""))
    except httpx.HTTPError as exc:
        raise BillingError(f"Stripe unreachable: {exc}") from exc
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code >= 400:
        raise BillingError((body.get("error") or {}).get("message") or f"Stripe error {r.status_code}")
    return body


def create_checkout(tenant, email: str) -> str:
    data = {
        "mode": "subscription",
        "line_items[0][price]": settings.STRIPE_PRICE_ID,
        "line_items[0][quantity]": "1",
        "client_reference_id": tenant.id,
        "metadata[tenant_id]": tenant.id,
        "subscription_data[metadata][tenant_id]": tenant.id,
        "success_url": f"{settings.APP_URL}/dashboard?billing=success",
        "cancel_url": f"{settings.APP_URL}/dashboard?billing=cancelled",
        "allow_promotion_codes": "true",
    }
    if tenant.stripe_customer_id:
        data["customer"] = tenant.stripe_customer_id
    else:
        data["customer_email"] = email
    return _post("/checkout/sessions", data)["url"]


def create_portal(tenant) -> str:
    if not tenant.stripe_customer_id:
        raise BillingError("No subscription yet")
    return _post("/billing_portal/sessions", {"customer": tenant.stripe_customer_id,
                                              "return_url": f"{settings.APP_URL}/dashboard"})["url"]


def verify_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> bool:
    """Stripe-Signature: t=<ts>,v1=<hex hmac of "<ts>.<payload>">[,v1=...]"""
    if not header or not secret:
        return False
    parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
    ts = next((v for k, v in parts if k == "t"), None)
    sigs = [v for k, v in parts if k == "v1"]
    if not ts or not sigs:
        return False
    try:
        if abs((now or time.time()) - int(ts)) > SIGNATURE_TOLERANCE:
            return False
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


def apply_event(db, event: dict) -> str | None:
    """Update the tenant a Stripe event concerns. Returns the tenant id or None."""
    from . import models

    kind = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    if kind == "checkout.session.completed":
        tenant_id = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("tenant_id")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first() if tenant_id else None
        if not tenant:
            return None
        tenant.stripe_customer_id = obj.get("customer") or tenant.stripe_customer_id
        tenant.stripe_subscription_id = obj.get("subscription") or tenant.stripe_subscription_id
        tenant.subscription_status = "active"
        tenant.plan = "pro"
        db.commit()
        return tenant.id
    if kind.startswith("customer.subscription."):
        tenant_id = (obj.get("metadata") or {}).get("tenant_id")
        q = db.query(models.Tenant)
        tenant = (q.filter(models.Tenant.id == tenant_id).first() if tenant_id else None) or (
            q.filter(models.Tenant.stripe_customer_id == obj.get("customer")).first()
            if obj.get("customer") else None)
        if not tenant:
            return None
        status = "canceled" if kind.endswith(".deleted") else obj.get("status", "")
        tenant.subscription_status = status
        tenant.stripe_subscription_id = obj.get("id") or tenant.stripe_subscription_id
        tenant.plan = "pro" if status in ACTIVE else "free"
        db.commit()
        return tenant.id
    return None
