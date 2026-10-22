"""Standalone tools: email header analyzer (public) and lookalike domain finder."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, header_analyzer, models, schemas
from ..database import get_db
from ..deps import client_ip, get_current_user, normalize_domain, rate_limit
from ..scanner import lookalike

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
