"""Billing: plan status, Stripe Checkout / Customer Portal, Stripe webhook."""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, billing, models
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, require_owner

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.get("")
def billing_status(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"configured": billing.configured(), "plan": t.plan,
            "status": t.subscription_status, "pro_features": billing.is_pro(t),
            "monitor_limit": billing.monitor_limit(t), "has_subscription": bool(t.stripe_customer_id)}


@router.post("/checkout")
def checkout(request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(require_owner)):
    if not billing.configured():
        raise HTTPException(status_code=503, detail="Billing isn't set up on this server")
    try:
        url = billing.create_checkout(user.tenant, user.email)
    except billing.BillingError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    audit.log_request(db, request, "billing.checkout", user)
    return {"url": url}


@router.post("/portal")
def portal(request: Request, db: Session = Depends(get_db),
           user: models.User = Depends(require_owner)):
    if not billing.configured():
        raise HTTPException(status_code=503, detail="Billing isn't set up on this server")
    try:
        url = billing.create_portal(user.tenant)
    except billing.BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"url": url}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    if not billing.verify_signature(payload, request.headers.get("stripe-signature", ""),
                                    settings.STRIPE_WEBHOOK_SECRET):
        raise HTTPException(status_code=400, detail="Invalid signature")
    try:
        event = json.loads(payload)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    tenant_id = billing.apply_event(db, event)
    if tenant_id:
        audit.log(db, "billing." + event.get("type", "event"), tenant_id=tenant_id,
                  detail={"event_id": event.get("id")})
    return {"received": True}
