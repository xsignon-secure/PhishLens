"""Server-rendered pages: landing, auth, dashboard, reports."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pathlib import Path

from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import models
from ..config import settings
from ..database import get_db
from ..deps import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent.parent / "templates")
templates.env.globals.update(contact_email=settings.CONTACT_EMAIL, source_url=settings.SOURCE_URL)


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


@router.get("/tools/headers", response_class=HTMLResponse)
def headers_tool(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "headers.html", {"request": request, "user": _user_or_none(request, db)})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@router.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request, "signup.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = _user_or_none(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", {"request": request, "user": user})


@router.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request):
    return templates.TemplateResponse(request, "verify.html", {"request": request})


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(request, "forgot-password.html", {"request": request})


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request):
    return templates.TemplateResponse(request, "reset-password.html", {"request": request})


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
        {"request": request, "scan": scan, "user": _user_or_none(request, db), "brand": brand}
    )
