"""Server-rendered pages: landing, auth, dashboard, reports."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import hashlib
from pathlib import Path

from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import i18n, models
from ..scanner import engine
from ..config import settings
from ..database import get_db
from ..deps import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent.parent / "templates")
templates.env.globals.update(contact_email=settings.CONTACT_EMAIL, source_url=settings.SOURCE_URL)
i18n.install(templates.env)


def _asset_version() -> str:
    """Short hash of the CSS and JS, added as ?v= so browsers fetch new copies
    after a deploy instead of running a cached app.js against new pages."""
    static = Path(__file__).resolve().parent.parent / "static"
    h = hashlib.sha256()
    for name in ("app.js", "style.css"):
        f = static / name
        if f.exists():
            h.update(f.read_bytes())
    return h.hexdigest()[:10]


templates.env.globals["asset_v"] = _asset_version()


def _user_or_none(request: Request, db: Session):
    try:
        return get_current_user(request, None, db)
    except Exception:
        return None


@router.get("/", response_class=HTMLResponse)
def landing(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "index.html", {"request": request, "user": _user_or_none(request, db)})


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "help.html", {"request": request, "user": _user_or_none(request, db)})


@router.get("/tools", response_class=HTMLResponse)
def tools_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "tools.html", {"request": request, "user": _user_or_none(request, db)})


@router.get("/tools/headers", response_class=HTMLResponse)
def headers_tool(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "headers.html", {"request": request, "user": _user_or_none(request, db)})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@router.get("/platform", response_class=HTMLResponse)
def platform_page(request: Request):
    return templates.TemplateResponse(request, "platform.html",
                                      {"request": request, "enabled": bool(settings.ADMIN_PASSWORD),
                                       "plans_enabled": settings.PLANS_ENABLED})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = _user_or_none(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", {"request": request, "user": user})


@router.get("/setup", response_class=HTMLResponse)
def setup_wizard(request: Request, db: Session = Depends(get_db)):
    user = _user_or_none(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "setup.html", {"request": request, "user": user})


@router.get("/overview", response_class=HTMLResponse)
def overview_page(request: Request, db: Session = Depends(get_db)):
    user = _user_or_none(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "overview.html", {"request": request, "user": user})


@router.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html", {"request": request})


@router.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html", {"request": request})


@router.get("/r/{scan_id}", response_class=HTMLResponse)
def shared_report(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.is_public.is_(True)).first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", {"request": request}, status_code=404)
    from .. import branding
    tenant = (db.query(models.Tenant).filter(models.Tenant.id == scan.tenant_id).first()
              if scan.tenant_id else None)
    brand = branding.for_tenant(tenant)
    if brand:
        brand = {k: brand[k] for k in ("name", "color", "footer", "logo_data_url")}
    return templates.TemplateResponse(
        request, "report.html",
        {"request": request, "scan": scan, "result": engine.with_guides(scan.result),
         "user": _user_or_none(request, db), "brand": brand}
    )
