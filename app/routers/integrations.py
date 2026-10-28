"""Team settings for SIEM export and PSA tickets (see app/integrations.py)."""
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, integrations, models
from ..database import get_db
from ..deps import rate_limit, require_owner

router = APIRouter(prefix="/api/team", tags=["integrations"])
_KINDS = {"siem": integrations.clean_siem, "psa": integrations.clean_psa}


def _which(which: str) -> str:
    if which not in _KINDS:
        raise HTTPException(status_code=404, detail="Not found")
    return which


@router.get("/integrations")
def get_integrations(db: Session = Depends(get_db), user: models.User = Depends(require_owner)):
    t = user.tenant
    return {"siem": integrations.public_view(t.siem), "psa": integrations.public_view(t.psa),
            "alert_kinds": list(integrations.ALERT_KINDS)}


@router.put("/integrations/{which}")
def put_integration(which: str, request: Request, payload: dict = Body(...), db: Session = Depends(get_db),
                    user: models.User = Depends(require_owner)):
    which = _which(which)
    t = user.tenant
    try:
        clean = _KINDS[which](payload, getattr(t, which))
    except integrations.ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    setattr(t, which, clean)
    db.commit()
    audit.log_request(db, request, f"{which}.update", user, {"kind": clean["kind"]})
    return integrations.public_view(clean)


@router.delete("/integrations/{which}")
def delete_integration(which: str, request: Request, db: Session = Depends(get_db),
                       user: models.User = Depends(require_owner)):
    which = _which(which)
    setattr(user.tenant, which, None)
    db.commit()
    audit.log_request(db, request, f"{which}.delete", user)
    return {"ok": True}


@router.post("/integrations/{which}/test")
def test_integration(which: str, request: Request, db: Session = Depends(get_db),
                     user: models.User = Depends(require_owner)):
    which = _which(which)
    cfg = getattr(user.tenant, which)
    if not cfg:
        raise HTTPException(status_code=400, detail="Nothing configured yet")
    rate_limit(request, f"integration-test:{user.tenant_id}", 20)
    event = [integrations.test_event()]
    try:
        if which == "siem":
            ok, detail = integrations.send_siem(cfg, event), None
        else:
            ticket = integrations.create_ticket(cfg, event)
            ok, detail = bool(ticket), ticket
    except Exception as exc:  # show the team why: wrong key, unreachable host...
        ok, detail = False, str(exc)[:300]
    audit.log_request(db, request, f"{which}.test", user, {"ok": ok})
    return {"ok": ok, "detail": detail}
