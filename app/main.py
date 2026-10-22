"""PhishLens — deterministic email-security scanner, multi-tenant SaaS."""
import contextvars
import hmac
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import init_db
from .routers import auth, billing, dmarc, hosted, monitors, pages, scans, sso, team, tools

# A ContextVar (not threading.local): concurrent async requests share one
# event-loop thread, so a thread-local would leak IDs between requests.
_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

APP_DIR = Path(__file__).resolve().parent


class _RequestIdFormatter(logging.Formatter):
    def format(self, record):
        record.request_id = _request_id.get()
        return super().format(record)


logging.basicConfig(level=logging.INFO)
for _h in logging.root.handlers:
    _h.setFormatter(_RequestIdFormatter(
        "%(asctime)s %(levelname)s %(name)s %(request_id)s %(message)s"))
log = logging.getLogger("phishlens")

@asynccontextmanager
async def lifespan(app):
    init_db()
    if settings.SECRET_KEY == "dev-only-change-me":
        log.warning("SECRET_KEY is the development default: set a long random value before deploying")
    yield


app = FastAPI(title=settings.APP_NAME, docs_url="/api/docs", redoc_url=None, lifespan=lifespan)


# Endpoints that establish a session/credential, or need no session at all
# (they are authorized by credentials/tokens in the body, not by cookies)
_CSRF_EXEMPT = {
    "/api/auth/signup", "/api/auth/login", "/api/auth/mfa/challenge",
    "/api/auth/password/forgot", "/api/auth/password/reset",
    "/api/auth/verify", "/api/scans/public", "/api/tools/headers",
    "/api/billing/webhook",
}


@app.middleware("http")
async def csrf_protect(request, call_next):
    """Double-submit CSRF: cookie-authenticated API mutations must echo the
    csrf_token cookie in the X-CSRF-Token header.

    Applies only when the cookie is what authenticates the request — explicit
    Authorization/API-key headers are exempt, as are the endpoints that
    establish the session itself (they're authorized by credentials, not cookies)."""
    if (
        request.url.path.startswith("/api/")
        and request.method in ("POST", "PUT", "PATCH", "DELETE")
        and request.url.path not in _CSRF_EXEMPT
        and request.cookies.get("access_token")
        and not request.headers.get("authorization")
        and not request.headers.get("x-api-key")
    ):
        token = request.headers.get("x-csrf-token")
        expected = request.cookies.get("csrf_token")
        if not expected or not token or not hmac.compare_digest(token, expected):
            return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
    return await call_next(request)

@app.middleware("http")
async def mta_sts_policy_host(request, call_next):
    """Serve hosted MTA-STS policies: customers CNAME mta-sts.<domain> here."""
    host = (request.headers.get("host") or "").split(":")[0].lower().rstrip(".")
    if host.startswith("mta-sts.") and request.url.path == "/.well-known/mta-sts.txt":
        from fastapi.responses import PlainTextResponse

        from . import hosted as hosted_mod
        from .database import SessionLocal
        db = SessionLocal()
        try:
            rec = hosted_mod.serving_record(db, host[len("mta-sts."):])
            if not rec:
                return PlainTextResponse("No MTA-STS policy hosted for this domain\n", status_code=404)
            return PlainTextResponse(hosted_mod.mta_sts_policy(rec.config),
                                     headers={"Cache-Control": "max-age=300"})
        finally:
            db.close()
    return await call_next(request)

# Security response headers
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.APP_URL.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Registered last so it is the outermost middleware: every response, including
# CSRF rejections, carries X-Request-ID and is logged.
@app.middleware("http")
async def request_context(request, call_next):
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex[:12]
    request.state.request_id = request_id
    token = _request_id.set(request_id)
    start = time.time()
    try:
        response = await call_next(request)
        ms = (time.time() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        log.info("%s %s -> %s (%.0fms)", request.method, request.url.path,
                 response.status_code, ms)
        return response
    except Exception:
        log.exception("%s %s -> unhandled error", request.method, request.url.path)
        raise
    finally:
        _request_id.reset(token)


if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-CSRF-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

# Absolute paths: the app (and scripts/rescan.py) must work from any cwd.
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(monitors.router)
app.include_router(team.router)
app.include_router(dmarc.router)
app.include_router(tools.router)
app.include_router(billing.router)
app.include_router(sso.router)
app.include_router(hosted.router)


@app.get("/api/health")
def health():
    return {"ok": True, "app": settings.APP_NAME}


@app.exception_handler(404)
async def not_found(request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    from .routers.pages import templates
    return templates.TemplateResponse(
        request, "404.html", {"request": request, "user": None}, status_code=404
    )
