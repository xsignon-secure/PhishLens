"""Hosted plans: Free, Pro and MSP.

Only used when PLANS_ENABLED is on (the hosted service). A self-hosted copy
leaves it off and every company gets everything. Limits are enforced here,
on the server; the dashboard only shows them.
"""
from datetime import datetime, timedelta

from fastapi import HTTPException

from .config import settings

PRO_FEATURES = frozenset({
    "ruf", "tls_rpt", "lookalike_watch", "hosted", "dns_fixes",
    "scheduled_reports", "share", "webhook", "api_keys",
})
MSP_FEATURES = PRO_FEATURES | {"white_label", "siem_psa", "mcp"}

# None = unlimited. rescan_hours is the shortest gap between automatic rescans
# (the scheduler's own RESCAN_INTERVAL_HOURS still sets how often it runs).
PLANS = {
    "free": {"label": "Free", "monitors": 2, "users": 2, "rescan_hours": 168,
             "dmarc_domains": 1, "dmarc_days": 14, "audit_days": 7, "features": frozenset()},
    "pro": {"label": "Pro", "monitors": 25, "users": 10, "rescan_hours": 24,
            "dmarc_domains": None, "dmarc_days": 365, "audit_days": 90, "features": PRO_FEATURES},
    "msp": {"label": "MSP", "monitors": None, "users": None, "rescan_hours": 1,
            "dmarc_domains": None, "dmarc_days": 730, "audit_days": 365, "features": MSP_FEATURES},
}
# Which plan first has each feature, for the "needs Pro" message.
FEATURE_NAMES = {
    "ruf": "DMARC failure reports", "tls_rpt": "TLS reports", "lookalike_watch": "Lookalike monitoring",
    "hosted": "Hosted records", "dns_fixes": "One-click DNS fixes", "scheduled_reports": "Scheduled reports",
    "share": "Shared report links", "webhook": "Alert webhooks", "api_keys": "API keys",
    "white_label": "White-label", "siem_psa": "SIEM and PSA", "mcp": "AI assistant connection (MCP)",
}


def enabled() -> bool:
    return bool(settings.PLANS_ENABLED)


def plan_key(tenant) -> str:
    """The company's plan. With plans off, everyone is on the top plan."""
    if not enabled():
        return "msp"
    key = getattr(tenant, "plan", None) or "free"
    return key if key in PLANS else "free"


def plan(tenant) -> dict:
    return PLANS[plan_key(tenant)]


def has(tenant, feature: str) -> bool:
    return feature in plan(tenant)["features"]


def _needed(feature: str) -> str:
    return "Pro" if feature in PRO_FEATURES else "MSP"


def require(tenant, feature: str) -> None:
    """402 when the company's plan doesn't include this feature."""
    if not has(tenant, feature):
        raise HTTPException(status_code=402, detail=(
            f"{FEATURE_NAMES.get(feature, feature)} needs the {_needed(feature)} plan. "
            "Ask the administrator of this service to upgrade your company."))


def check_limit(tenant, key: str, current: int, what: str) -> None:
    """402 when adding one more would go over the plan's limit."""
    limit = plan(tenant)[key]
    if limit is not None and current >= limit:
        raise HTTPException(status_code=402, detail=(
            f"Your {plan(tenant)['label']} plan includes {limit} {what}. "
            "Ask the administrator of this service to upgrade your company."))


def days_cap(tenant, key: str, asked: int) -> int:
    """Clamp a look-back window (DMARC reports, audit log) to the plan's history."""
    return max(1, min(asked, plan(tenant)[key]))


def since(tenant, key: str) -> datetime:
    return datetime.utcnow() - timedelta(days=plan(tenant)[key])


def summary(tenant, usage: dict | None = None) -> dict:
    p = plan(tenant)
    return {"enabled": enabled(), "plan": plan_key(tenant), "label": p["label"],
            "limits": {k: p[k] for k in ("monitors", "users", "rescan_hours", "dmarc_domains",
                                          "dmarc_days", "audit_days")},
            "features": sorted(p["features"]), "usage": usage or {}}
