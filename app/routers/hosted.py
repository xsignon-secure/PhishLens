"""Hosted DMARC / SPF / MTA-STS records, and one-click DNS fixes through the
customer's own Cloudflare account."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, crypto, dns_providers, hosted, models
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, normalize_domain, require_pro_owner

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
                db: Session = Depends(get_db), user: models.User = Depends(require_pro_owner)):
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
    if kind == "mta_sts" and (created or rec.config != cfg):
        rec.policy_id = hosted.new_policy_id()  # receivers refetch the policy when the id changes
    rec.config = cfg
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
                  user: models.User = Depends(require_pro_owner)):
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
class CloudflareTokenIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class DnsApplyIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: str = Field(pattern="^(TXT|CNAME)$")
    value: str = Field(min_length=1, max_length=2000)


_TXT_PREFIXES = ("v=spf1", "v=dmarc1", "v=stsv1", "v=tlsrptv1", "v=bimi1")


@router.get("/api/team/cloudflare")
def cloudflare_status(user: models.User = Depends(get_current_user)):
    return {"connected": bool(user.tenant.cloudflare_token)}


@router.put("/api/team/cloudflare")
def set_cloudflare(payload: CloudflareTokenIn, request: Request, db: Session = Depends(get_db),
                   user: models.User = Depends(require_pro_owner)):
    try:
        ok = dns_providers.Cloudflare(payload.token.strip()).verify()
    except dns_providers.DnsProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=400, detail="Cloudflare says this token isn't active")
    user.tenant.cloudflare_token = crypto.encrypt(payload.token.strip())
    db.commit()
    audit.log_request(db, request, "dns.cloudflare_connect", user)
    return {"connected": True}


@router.delete("/api/team/cloudflare")
def delete_cloudflare(request: Request, db: Session = Depends(get_db),
                      user: models.User = Depends(require_pro_owner)):
    user.tenant.cloudflare_token = None
    db.commit()
    audit.log_request(db, request, "dns.cloudflare_disconnect", user)
    return {"ok": True}


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
                 user: models.User = Depends(require_pro_owner)):
    token = crypto.decrypt(user.tenant.cloudflare_token)
    if not token:
        raise HTTPException(status_code=400, detail="Connect Cloudflare first")
    name = check_apply_allowed(payload.name, payload.type, payload.value,
                               _tenant_domains(db, user.tenant_id))
    cf = dns_providers.Cloudflare(token)
    try:
        zone_id, _ = cf.zone_for(name)
        result = cf.upsert(zone_id, name, payload.type, payload.value)
    except dns_providers.DnsProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    audit.log_request(db, request, "dns.apply", user,
                      {"name": name, "type": payload.type, "value": payload.value[:200], "result": result})
    return {"ok": True, "result": result, "name": name}
