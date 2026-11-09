"""Public sign-up: a free company account for anyone with a working email.

The step-by-step fix guides are for signed-in accounts, so people need a way
to get one without waiting for the platform admin. Sign-up creates a company
on the Free plan with the visitor as its owner, and sends the login details
to the address typed in: nobody can sign in without reading that inbox, so
the address is verified by design. Everything after that is the normal
first login (choose a password, then set up two-factor, required for owners).

Abuse controls: off unless SIGNUP_ENABLED, per-IP and server-wide hourly caps,
a honeypot field, a check that the email domain exists, a short list of
throwaway-mail domains, and the same answer whether or not the address is
already registered (no account discovery).
"""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, mailer, models
from ..config import settings
from ..database import get_db
from ..deps import client_ip, rate_limit
from .platform import _Platform
from .users import EMAIL_RE, _create, _queue_credentials

router = APIRouter(prefix="/api/auth", tags=["auth"])

DONE = {"ok": True, "message": "Check your inbox: your login details are on the way. "
                               "If nothing arrives in a few minutes, check spam or try logging in."}

# Throwaway inbox services. Not complete, and doesn't need to be: the hourly
# caps do the real work.
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "yopmail.com", "trashmail.com", "getnada.com", "dispostable.com",
    "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mintemail.com", "mohmal.com", "emailondeck.com",
}


class SignupIn(BaseModel):
    company: str = Field(min_length=1, max_length=200)
    full_name: str = Field(default="", max_length=200)
    email: str = Field(min_length=3, max_length=320)
    accept_terms: bool = False
    # Honeypot: hidden in the form, so only bots fill it in.
    website: str = Field(default="", max_length=200)
    # "Email me the fix guide" on a free report: the guide for this landing-
    # page scan goes to the new account's address with the login details.
    scan_id: str | None = Field(default=None, max_length=64)
    model_config = {"extra": "forbid"}


def mail_domain_ok(domain: str) -> bool:
    """The email's domain exists in DNS (so mail to it can be delivered)."""
    from ..deps import _domain_exists_in_dns
    return _domain_exists_in_dns(domain)


def enabled() -> bool:
    return settings.SIGNUP_ENABLED and mailer.server_config() is not None


@router.post("/signup", status_code=202)
def signup(payload: SignupIn, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    if not settings.SIGNUP_ENABLED:
        raise HTTPException(status_code=404, detail="Sign-up is not open on this server")
    if not mailer.server_config():
        raise HTTPException(status_code=503, detail="Sign-up needs the server's mail settings (SMTP_*)")
    rate_limit(request, f"signup:{client_ip(request)}", settings.SIGNUPS_PER_IP_PER_HOUR)
    rate_limit(request, "signup:all", settings.SIGNUPS_PER_HOUR)
    if not payload.accept_terms:
        raise HTTPException(status_code=400, detail="Please accept the terms to create an account")
    email = payload.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    domain = email.rsplit("@", 1)[1]
    if domain in DISPOSABLE:
        raise HTTPException(status_code=400, detail="Please use your work email address")
    if payload.website:
        return DONE
    if not mail_domain_ok(domain):
        raise HTTPException(status_code=400, detail="That email domain doesn't exist")
    if db.query(models.User).filter(models.User.email == email).first():
        audit.log_request(db, request, "signup.existing", detail={"email": email})
        return DONE
    tenant = models.Tenant(name=payload.company.strip(), plan="free")
    db.add(tenant)
    db.flush()
    owner, temp = _create(db, _Platform(tenant.id), email, payload.full_name, "owner")
    _queue_credentials(request, background, owner, temp, True, db)
    audit.log(db, "signup", owner, tenant_id=tenant.id, ip=client_ip(request),
              detail={"owner": email, "with_guide": bool(payload.scan_id)})
    if payload.scan_id:
        scan = db.query(models.Scan).filter(models.Scan.id == payload.scan_id,
                                            models.Scan.tenant_id.is_(None)).first()
        if scan:
            background.add_task(send_fix_guide, scan.id, email)
    return DONE


def send_fix_guide(scan_id: str, email: str) -> None:
    """Email the fix guide PDF for an anonymous scan to a newly signed-up
    address (the address is the account's, so this sends nothing to anyone
    who didn't ask for an account)."""
    from ..database import SessionLocal
    from .scans import _pdf_bytes
    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        if not scan:
            return
        pdf, filename = _pdf_bytes(scan, db, kind="guide")
        body = (f"Here is the step-by-step fix guide for {scan.domain}.\n\n"
                f"Your login details are in a separate email. Sign in to see the fixes for every scan, "
                f"publish records in one click and get alerts: {settings.APP_URL}/login\n")
        mailer.send_email([email], f"Fix guide for {scan.domain}", body,
                          attachments=[(filename, pdf, "application/pdf")])
    finally:
        db.close()
