"""Report-phish button (Outlook add-in, Gmail add-on): admin setup, the
report endpoint the add-ins call, and the files they need."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from .. import audit, mailer, models, report_button
from ..database import get_db
from ..deps import client_ip, get_current_user, rate_limit, require_admin, require_step_up
from .pages import templates
from .phish import ingest

router = APIRouter(tags=["report button"])
MAX_BODY = 25 * 1024 * 1024
REPORTS_PER_HOUR = 300


def _files(tenant: models.Tenant, token: str) -> dict:
    return {"token": token, "outlook_manifest": report_button.outlook_manifest(tenant, token),
            "gmail_script": report_button.gmail_script(tenant, token),
            "gmail_manifest": report_button.gmail_manifest()}


@router.get("/api/report-button")
def status(user: models.User = Depends(get_current_user)):
    t = user.tenant
    return {"enabled": bool(t.report_token_hash),
            "created_at": t.report_token_created_at.isoformat() + "Z" if t.report_token_created_at else None}


@router.post("/api/report-button/token")
def make_token(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_step_up)):
    """A new token (the old one stops working) and the add-in files with it
    inside. The token is shown only now; it is stored hashed."""
    token = report_button.new_token(db, user.tenant)
    audit.log_request(db, request, "report_button.token", user, {"severity": "high"})
    return _files(user.tenant, token)


@router.delete("/api/report-button/token", status_code=204)
def revoke_token(request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    report_button.revoke(db, user.tenant)
    audit.log_request(db, request, "report_button.revoke", user, {})
    return Response(status_code=204)


@router.post("/api/report-button/report", status_code=201)
async def report(request: Request, db: Session = Depends(get_db)):
    """Called by the add-ins: the raw email as the body, the company's token
    in X-Report-Token, the reporter's address in X-Reporter (as the mail
    client gives it; shown as such, not as a verified identity)."""
    rate_limit(request, f"report-button-ip:{client_ip(request)}", REPORTS_PER_HOUR)
    tenant = report_button.tenant_for(db, request.headers.get("x-report-token"))
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid report token")
    rate_limit(request, f"phish-report:{tenant.id}", REPORTS_PER_HOUR)
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Email too large")
    blob = await request.body()
    if len(blob) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Email too large")
    reporter = (request.headers.get("x-reporter") or "").strip()[:254]
    reporter = reporter if mailer.real_email(reporter) else "report button"
    out = ingest(db, request, tenant, reporter, blob, source="report_button")
    # The add-in shows only the verdict: the token can't read reports back.
    if out.get("simulation"):
        return {"id": out["id"], "verdict": "simulation", "simulation": True, "message": out["message"]}
    return {"id": out["id"], "verdict": out["verdict"]}


@router.get("/addins/outlook/taskpane.html", response_class=HTMLResponse)
def outlook_taskpane(request: Request):
    resp = templates.TemplateResponse(request, "addin_outlook.html", {"request": request})
    resp.headers["Content-Security-Policy"] = f"frame-ancestors 'self' {report_button.OUTLOOK_FRAME_ANCESTORS}"
    resp.headers["X-Addin-Frame"] = "1"  # tells the security-headers middleware not to add X-Frame-Options
    return resp


@router.get("/addins/icon-{size}.png")
def icon(size: int):
    if size not in report_button.ICON_SIZES:
        raise HTTPException(status_code=404)
    return Response(report_button.icon_png(size), media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})
