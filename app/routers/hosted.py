"""Hosted DMARC / SPF / MTA-STS / TLS-RPT / BIMI records, and one-click DNS fixes through the
customer's own DNS provider (Cloudflare, DigitalOcean or deSEC)."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, crypto, dns_providers, hosted, models, plans
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, require_admin

router = APIRouter(tags=["hosted"])


def _record_out(rec: models.HostedRecord, with_status: bool = False) -> dict:
    out = {"id": rec.id, "domain": rec.domain, "kind": rec.kind, "config": rec.config,
           "published": rec.published or {}, "customer_records": hosted.customer_records(rec),
           "updated_at": rec.updated_at.isoformat() + "Z"}
    if with_status:
        out["delegation"] = hosted.verify_delegation(rec)
    return out


def _tenant_domains(db: Session, tenant_id: str) -> set[str]:
    monitored = {d for (d,) in db.query(models.Monitor.domain).filter(models.Monitor.tenant_id == tenant_id)}
    scanned = {d for (d,) in db.query(models.Scan.domain).filter(models.Scan.tenant_id == tenant_id).distinct()}
    return monitored | scanned


@router.get("/api/hosted")
def list_hosted(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    recs = (db.query(models.HostedRecord).filter(models.HostedRecord.tenant_id == user.tenant_id)
            .order_by(models.HostedRecord.domain, models.HostedRecord.kind).all())
    return {"configured": hosted.configured(), "zone": settings.HOSTED_ZONE or None,
            "default_rua": settings.HOSTED_DMARC_RUA or None,
            "records": [_record_out(r) for r in recs]}


class HostedIn(BaseModel):
    config: dict


@router.put("/api/hosted/{domain}/{kind}")
def save_hosted(domain: str, kind: str, payload: HostedIn, request: Request,
                db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "hosted")
    if not hosted.configured():
        raise HTTPException(status_code=503, detail="Hosted records aren't set up on this server")
    domain = normalize_domain(domain)
    if kind not in hosted.KINDS:
        raise HTTPException(status_code=404, detail="Unknown record kind")
    if domain not in _tenant_domains(db, user.tenant_id):
        raise HTTPException(status_code=400, detail="Scan or monitor this domain first")
    try:
        cfg = hosted.clean_config(kind, payload.config, domain)
    except hosted.HostedError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    rec = (db.query(models.HostedRecord)
           .filter(models.HostedRecord.tenant_id == user.tenant_id, models.HostedRecord.domain == domain,
                   models.HostedRecord.kind == kind).first())
    created = rec is None
    if created:
        rec = models.HostedRecord(tenant_id=user.tenant_id, domain=domain, kind=kind, config=cfg)
        db.add(rec)
    if kind in ("mta_sts", "bimi") and (created or rec.config != cfg):
        rec.policy_id = hosted.new_policy_id()  # receivers refetch the policy / logo when the id changes
    rec.config = cfg
    db.flush()  # assigns rec.id, which the hosted BIMI logo URL uses
    try:
        hosted.publish(rec)
    except (hosted.HostedError, dns_providers.DnsProviderError) as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Saved by someone else at the same time: reload")
    if kind == "mta_sts" and created:
        hosted.add_render_domain(f"mta-sts.{domain}")
    audit.log_request(db, request, "hosted.save", user, {"domain": domain, "kind": kind})
    return _record_out(rec)


@router.get("/bimi/{rec_id}/{name}.svg", include_in_schema=False)
def bimi_logo(rec_id: str, name: str, db: Session = Depends(get_db)):
    """Public: a hosted BIMI logo. Only logos that passed the SVG Tiny PS
    check are stored, and the CSP keeps any SVG inert if opened directly."""
    rec = (db.query(models.HostedRecord)
           .filter(models.HostedRecord.id == rec_id, models.HostedRecord.kind == "bimi").first())
    if not rec:
        raise HTTPException(status_code=404, detail="Logo not found")
    return Response(rec.config["svg"], media_type="image/svg+xml", headers={
        "Cache-Control": "public, max-age=3600",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})


@router.get("/api/hosted/{domain}/{kind}/status")
def hosted_status(domain: str, kind: str, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    rec = (db.query(models.HostedRecord)
           .filter(models.HostedRecord.tenant_id == user.tenant_id,
                   models.HostedRecord.domain == normalize_domain(domain),
                   models.HostedRecord.kind == kind).first())
    if not rec:
        raise HTTPException(status_code=404, detail="Not hosted")
    return _record_out(rec, with_status=True)


@router.delete("/api/hosted/{domain}/{kind}")
def delete_hosted(domain: str, kind: str, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_admin)):
    rec = (db.query(models.HostedRecord)
           .filter(models.HostedRecord.tenant_id == user.tenant_id,
                   models.HostedRecord.domain == normalize_domain(domain),
                   models.HostedRecord.kind == kind).first())
    if not rec:
        raise HTTPException(status_code=404, detail="Not hosted")
    try:
        hosted.unpublish(rec)
    except dns_providers.DnsProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    db.delete(rec)
    db.commit()
    audit.log_request(db, request, "hosted.delete", user, {"domain": rec.domain, "kind": kind})
    return {"ok": True}


# ------------------------------------------------------------------ one-click fixes
class DnsTokenIn(BaseModel):
    provider: str = Field(default="cloudflare", pattern="^(cloudflare|digitalocean|desec|godaddy|route53)$")
    token: str = Field(min_length=20, max_length=200)


class DnsApplyIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: str = Field(pattern="^(TXT|CNAME)$")
    value: str = Field(min_length=1, max_length=2000)


_TXT_PREFIXES = ("v=spf1", "v=dmarc1", "v=stsv1", "v=tlsrptv1", "v=bimi1")


def _dns_status(tenant) -> dict:
    return {"connected": bool(tenant.dns_token), "provider": tenant.dns_provider if tenant.dns_token else None,
            "label": dns_providers.LABELS.get(tenant.dns_provider or "", None)}


@router.get("/api/team/dns")
def dns_status(user: models.User = Depends(get_current_user)):
    return _dns_status(user.tenant)


@router.put("/api/team/dns")
def set_dns(payload: DnsTokenIn, request: Request, db: Session = Depends(get_db),
            user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "dns_fixes")
    token = payload.token.strip()
    try:
        ok = dns_providers.client(payload.provider, token).verify()
    except dns_providers.DnsProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=400, detail=f"{dns_providers.LABELS[payload.provider]} says this token isn't active")
    user.tenant.dns_provider = payload.provider
    user.tenant.dns_token = crypto.encrypt(token)
    db.commit()
    audit.log_request(db, request, "dns.connect", user, {"provider": payload.provider})
    return _dns_status(user.tenant)


@router.delete("/api/team/dns")
def delete_dns(request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(require_admin)):
    user.tenant.dns_provider = None
    user.tenant.dns_token = None
    db.commit()
    audit.log_request(db, request, "dns.disconnect", user)
    return {"ok": True}


# Older clients used /api/team/cloudflare; kept working.
@router.get("/api/team/cloudflare")
def cloudflare_status(user: models.User = Depends(get_current_user)):
    return {"connected": bool(user.tenant.dns_token) and user.tenant.dns_provider == "cloudflare"}


@router.put("/api/team/cloudflare")
def set_cloudflare(payload: DnsTokenIn, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "dns_fixes")
    payload.provider = "cloudflare"
    set_dns(payload, request, db, user)
    return {"connected": True}


@router.delete("/api/team/cloudflare")
def delete_cloudflare(request: Request, db: Session = Depends(get_db),
                      user: models.User = Depends(require_admin)):
    return delete_dns(request, db, user)


def check_apply_allowed(name: str, rtype: str, value: str, domains: set[str]) -> str:
    name = name.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+", name):
        raise HTTPException(status_code=400, detail="Invalid record name")
    if not any(name == d or name.endswith("." + d) for d in domains):
        raise HTTPException(status_code=403, detail="You can only change records for domains you scan or monitor")
    if rtype == "TXT":
        if not value.strip().strip('"').lower().startswith(_TXT_PREFIXES):
            raise HTTPException(status_code=400, detail="Only SPF, DMARC, MTA-STS, TLS-RPT and BIMI records can be applied")
    else:
        target = value.strip().rstrip(".").lower()
        allowed = [z for z in (settings.HOSTED_ZONE, hosted.mta_sts_target()) if z]
        if not any(target == z or target.endswith("." + z) for z in allowed):
            raise HTTPException(status_code=400, detail="CNAMEs can only point at PhishLens hosted records")
    return name


@router.post("/api/dns/apply")
def apply_record(payload: DnsApplyIn, request: Request, db: Session = Depends(get_db),
                 user: models.User = Depends(require_admin)):
    plans.require(user.tenant, "dns_fixes")
    token = crypto.decrypt(user.tenant.dns_token)
    if not token:
        raise HTTPException(status_code=400, detail="Connect your DNS provider first")
    name = check_apply_allowed(payload.name, payload.type, payload.value,
                               _tenant_domains(db, user.tenant_id))
    try:
        dns = dns_providers.client(user.tenant.dns_provider or "cloudflare", token)
        zone_id, _ = dns.zone_for(name)
        result = dns.upsert(zone_id, name, payload.type, payload.value)
    except dns_providers.DnsProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    audit.log_request(db, request, "dns.apply", user,
                      {"name": name, "type": payload.type, "value": payload.value[:200], "result": result,
                       "provider": user.tenant.dns_provider})
    return {"ok": True, "result": result, "name": name}


# ------------------------------------------------------------------ Domain Connect
@router.get("/api/dns/domain-connect")
def domain_connect_status(domain: str, request: Request, db: Session = Depends(get_db),
                          user: models.User = Depends(get_current_user)):
    """Can this domain's DNS host publish records with Domain Connect?"""
    from .. import domain_connect

    if not domain_connect.configured():
        return {"configured": False, "supported": False}
    domain = normalize_domain(domain)
    if domain not in _tenant_domains(db, user.tenant_id):
        raise HTTPException(status_code=403, detail="Scan or monitor this domain first")
    rate_limit(request, f"dc-discover:{user.tenant_id}", 120)
    info = domain_connect.discover(domain)
    if not info:
        return {"configured": True, "supported": False}
    return {"configured": True, "supported": True, "provider": info["provider_name"], "zone": info["zone"]}


@router.post("/api/dns/domain-connect/apply-url")
def domain_connect_apply_url(payload: DnsApplyIn, request: Request, db: Session = Depends(get_db),
                             user: models.User = Depends(require_admin)):
    """A signed link that opens the DNS host's approval screen for one
    record. Nothing changes until the user approves it there."""
    plans.require(user.tenant, "dns_fixes")
    from .. import domain_connect

    if not domain_connect.configured():
        raise HTTPException(status_code=503, detail="Domain Connect isn't set up on this server")
    rate_limit(request, f"dc-apply:{user.tenant_id}", 60)
    name = check_apply_allowed(payload.name, payload.type, payload.value, _tenant_domains(db, user.tenant_id))
    info = domain_connect.discover(name)
    if not info:
        raise HTTPException(status_code=400, detail="This domain's DNS host doesn't support Domain Connect")
    try:
        service_id, host, variables = domain_connect.match_service(name, payload.type, payload.value, info["zone"])
    except domain_connect.DomainConnectError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not domain_connect.supports(info, service_id):
        raise HTTPException(status_code=400, detail=f"{info['provider_name']} hasn't enabled the PhishLens template yet")
    url = domain_connect.apply_url(info, service_id, host, variables)
    audit.log_request(db, request, "dns.domain_connect", user,
                      {"name": name, "type": payload.type, "value": payload.value[:200],
                       "provider": info["provider_name"]})
    return {"url": url, "provider": info["provider_name"]}
