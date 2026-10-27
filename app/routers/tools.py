"""Standalone tools: email header analyzer, single-record checker and DNS
propagation checker (public), and lookalike domain finder (signed in)."""
from concurrent.futures import ThreadPoolExecutor

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, header_analyzer, models, schemas
from ..database import get_db
from ..deps import assert_public_target, client_ip, get_current_user, normalize_domain, public_scan_limit, rate_limit
from ..scanner import dns_checks, lookalike, mail_checks, net, web_checks

router = APIRouter(prefix="/api/tools", tags=["tools"])

LOOKALIKE_LIMIT_PER_HOUR = 10


@router.post("/headers")
def analyze_headers(payload: schemas.HeadersIn, request: Request):
    """Public and stateless: the pasted headers are analysed and discarded."""
    rate_limit(request, f"headers:{client_ip(request)}", 60)
    try:
        return header_analyzer.analyze(payload.headers)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/lookalikes")
def find_lookalikes(payload: schemas.LookalikeIn, request: Request, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    """Registered typosquats of a domain. Signed-in only: each run makes
    several hundred DNS queries."""
    rate_limit(request, f"lookalike:{user.tenant_id}", LOOKALIKE_LIMIT_PER_HOUR)
    domain = normalize_domain(payload.domain)
    result = lookalike.scan(domain)
    audit.log_request(db, request, "lookalike.scan", user,
                      {"domain": domain, "registered": len(result["registered"])})
    monitor = (db.query(models.Monitor)
               .filter(models.Monitor.tenant_id == user.tenant_id, models.Monitor.domain == domain)
               .first())
    if monitor:
        # A manual run refreshes the monitor's list too, so the scheduled check
        # alerts only on domains registered after what the user has already seen.
        from datetime import datetime
        monitor.lookalikes = sorted(r["domain"] for r in result["registered"])
        monitor.lookalikes_checked_at = datetime.utcnow()
        db.commit()
    return result


# ------------------------------------------------------------------ single-record checker
SINGLE_CHECKS = {
    "spf": dns_checks.check_spf, "dmarc": dns_checks.check_dmarc, "dkim": dns_checks.check_dkim,
    "mx": dns_checks.check_mx, "mta-sts": dns_checks.check_mta_sts, "tls-rpt": dns_checks.check_tls_rpt,
    "bimi": dns_checks.check_bimi, "caa": dns_checks.check_caa, "dnssec": dns_checks.check_dnssec,
    "blocklists": dns_checks.check_dnsbl, "dane": mail_checks.check_dane, "ptr": mail_checks.check_ptr,
    "ipv6": mail_checks.check_ipv6, "tls-cert": web_checks.check_tls_cert,
}


class CheckIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    check: str = Field(min_length=2, max_length=20)


@router.post("/check")
def check_one(payload: CheckIn, request: Request):
    """Public: run one check (e.g. just SPF) without a full scan or an account."""
    fn = SINGLE_CHECKS.get(payload.check)
    if not fn:
        raise HTTPException(status_code=404, detail="Unknown check")
    rate_limit(request, f"check:{client_ip(request)}", 60)
    domain = normalize_domain(payload.domain)
    assert_public_target(domain)
    try:
        return fn(domain)
    except dns_checks.DnsLookupError:
        raise HTTPException(status_code=503, detail="DNS servers didn't answer; try again shortly")


# ------------------------------------------------------------------ DNS propagation
RESOLVERS = {"Google": "8.8.8.8", "Cloudflare": "1.1.1.1", "Quad9": "9.9.9.9",
             "OpenDNS": "208.67.222.222", "Control D": "76.76.2.0", "AdGuard": "94.140.14.140"}
PROPAGATION_TYPES = ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "CAA", "TLSA")


class PropagationIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: str = Field(default="TXT", pattern="^(A|AAAA|MX|TXT|CNAME|NS|CAA|TLSA)$")


def _ask(server: str, name: str, rtype: str) -> list[str]:
    q = dns.message.make_query(name, rtype)
    r = dns.query.udp(q, server, timeout=3)
    if r.flags & dns.flags.TC:
        r = dns.query.tcp(q, server, timeout=4)
    out = []
    for rrset in r.answer:
        if rrset.rdtype == dns.rdatatype.from_text(rtype):
            for rd in rrset:
                out.append(b"".join(rd.strings).decode("utf-8", "replace") if rtype == "TXT" else rd.to_text())
    return sorted(out)


def _authoritative(name: str) -> dict[str, str]:
    """Up to two of the zone's own nameservers (the source of truth)."""
    try:
        zone = dns.resolver.zone_for_name(name, lifetime=4)
        out = {}
        for ns in list(dns.resolver.resolve(zone, "NS", lifetime=4))[:2]:
            host = str(ns.target).rstrip(".")
            ip = str(dns.resolver.resolve(host, "A", lifetime=4)[0])
            if net.is_public_ip(ip):  # never send queries to internal addresses
                out[f"{host} (authoritative)"] = ip
        return out
    except Exception:
        return {}


@router.post("/propagation")
def propagation(payload: PropagationIn, request: Request):
    """Public: what public resolvers and the zone's own nameservers return for
    a record, to see whether a change has propagated."""
    rate_limit(request, f"propagation:{client_ip(request)}", 60)
    name = payload.name.strip().rstrip(".").lower()
    labels = name.split(".")
    if len(labels) < 2 or not all(l and len(l) <= 63 for l in labels) or not all(
            c.isalnum() or c in "-_" for l in labels for c in l):
        raise HTTPException(status_code=400, detail="Invalid record name")
    normalize_domain(".".join(labels[-2:]))  # rejects IPs, .local, .internal and the like
    servers = {**_authoritative(name), **RESOLVERS}

    def one(item):
        label, ip = item
        try:
            return {"resolver": label, "ip": ip, "answers": _ask(ip, name, payload.type), "error": None}
        except Exception as exc:
            return {"resolver": label, "ip": ip, "answers": [], "error": type(exc).__name__}
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, servers.items()))
    answered = [tuple(r["answers"]) for r in results if not r["error"]]
    consistent = len(set(answered)) <= 1
    return {"name": name, "type": payload.type, "results": results, "consistent": consistent}
