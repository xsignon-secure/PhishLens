"""Threat feed for SIEMs: a TAXII 2.1 server with one collection, plus
STIX bundle, CSV and plain block-list downloads.

Auth is an API key: X-API-Key, "Authorization: Bearer plk_…", or HTTP Basic
with the key as the password (what Microsoft Sentinel's TAXII connector and
most firewalls send). A signed-in browser session works too, for downloads.
"""
import base64
import binascii
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .. import models, plans, threat_feed
from ..config import settings
from ..database import get_db
from ..deps import api_key_user, bearer_scheme, get_current_user, rate_limit

router = APIRouter(tags=["threat-feed"])

TAXII = "application/taxii+json;version=2.1"
MAX_PAGE = 1000


def feed_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
              db: Session = Depends(get_db)) -> models.User:
    auth = request.headers.get("authorization") or ""
    try:
        if auth[:6].lower() == "basic ":
            try:
                raw = base64.b64decode(auth[6:].strip(), validate=True).decode()
            except (binascii.Error, UnicodeDecodeError):
                raise HTTPException(status_code=401, detail="Invalid API key")
            key = raw.split(":", 1)[1] if ":" in raw else raw
            user = api_key_user(db, request, key)
        else:
            user = get_current_user(request, credentials, db)
    except HTTPException as exc:
        if exc.status_code == 401:
            raise HTTPException(status_code=401, detail=exc.detail,
                                headers={"WWW-Authenticate": 'Basic realm="PhishLens threat feed"'})
        raise
    tenant = db.get(models.Tenant, user.tenant_id)
    plans.require(tenant, "siem_psa")
    rate_limit(request, f"feed:{user.tenant_id}", 240, 3600)
    threat_feed.sync(db, tenant)
    request.state.tenant = tenant
    return user


def _taxii(body: dict, status: int = 200, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=TAXII, headers=headers)


def _root() -> str:
    return settings.APP_URL.rstrip("/") + "/taxii2/api/"


def _collection() -> dict:
    return {"id": threat_feed.COLLECTION_ID, "title": "PhishLens phishing indicators",
            "description": "Phishing domains, URLs and sender addresses found for your company.",
            "can_read": True, "can_write": False, "media_types": ["application/stix+json;version=2.1"]}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        raise HTTPException(status_code=400, detail="added_after must be an RFC 3339 timestamp")


def _check_collection(cid: str) -> None:
    if cid != threat_feed.COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Unknown collection")


# ------------------------------------------------------------------ TAXII 2.1
@router.get("/taxii2/")
def discovery(user: models.User = Depends(feed_user)):
    return _taxii({"title": "PhishLens threat feed", "default": _root(), "api_roots": [_root()]})


@router.get("/taxii2/api/")
def api_root(user: models.User = Depends(feed_user)):
    return _taxii({"title": "PhishLens", "versions": [TAXII], "max_content_length": 10_000_000})


@router.get("/taxii2/api/collections/")
def collections(user: models.User = Depends(feed_user)):
    return _taxii({"collections": [_collection()]})


@router.get("/taxii2/api/collections/{cid}/")
def collection(cid: str, user: models.User = Depends(feed_user)):
    _check_collection(cid)
    return _taxii(_collection())


def _page(db: Session, tenant_id: str, added_after: str | None, limit: int | None, next_: str | None,
          ids: str | None, types: str | None):
    q = db.query(models.ThreatIndicator).filter(models.ThreatIndicator.tenant_id == tenant_id)
    after = _parse_time(added_after)
    if after:
        q = q.filter(models.ThreatIndicator.modified > after)
    if ids:
        q = q.filter(models.ThreatIndicator.stix_id.in_([i.strip() for i in ids.split(",")][:100]))
    if types and "indicator" not in [t.strip() for t in types.split(",")]:
        return [], False, None
    try:
        offset = max(0, int(next_ or 0))
    except ValueError:
        raise HTTPException(status_code=400, detail="Bad next value")
    size = min(max(1, limit or MAX_PAGE), MAX_PAGE)
    rows = (q.order_by(models.ThreatIndicator.modified, models.ThreatIndicator.id)
            .offset(offset).limit(size + 1).all())
    more = len(rows) > size
    return rows[:size], more, str(offset + size) if more else None


def _range_headers(rows) -> dict:
    if not rows:
        return {}
    return {"X-TAXII-Date-Added-First": threat_feed._stamp(rows[0].modified),
            "X-TAXII-Date-Added-Last": threat_feed._stamp(rows[-1].modified)}


@router.get("/taxii2/api/collections/{cid}/objects/")
def objects(cid: str, request: Request, added_after: str | None = None, limit: int | None = Query(None, ge=1),
            next: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(feed_user)):
    _check_collection(cid)
    tenant = request.state.tenant
    rows, more, nxt = _page(db, tenant.id, added_after, limit, next,
                            request.query_params.get("match[id]"), request.query_params.get("match[type]"))
    objs = [threat_feed.to_stix(tenant, r) for r in rows]
    types = request.query_params.get("match[type]")
    if not next and not added_after and (not types or "identity" in types):
        objs.insert(0, threat_feed.identity(tenant))
    body = {"more": more, "objects": objs}
    if nxt:
        body["next"] = nxt
    return _taxii(body, headers=_range_headers(rows))


@router.get("/taxii2/api/collections/{cid}/manifest/")
def manifest(cid: str, request: Request, added_after: str | None = None, limit: int | None = Query(None, ge=1),
             next: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(feed_user)):
    _check_collection(cid)
    rows, more, nxt = _page(db, request.state.tenant.id, added_after, limit, next,
                            request.query_params.get("match[id]"), request.query_params.get("match[type]"))
    body = {"more": more, "objects": [
        {"id": r.stix_id, "date_added": threat_feed._stamp(r.modified), "version": threat_feed._stamp(r.modified),
         "media_type": "application/stix+json;version=2.1"} for r in rows]}
    if nxt:
        body["next"] = nxt
    return _taxii(body, headers=_range_headers(rows))


@router.get("/taxii2/api/collections/{cid}/objects/{oid}/")
def one_object(cid: str, oid: str, request: Request, db: Session = Depends(get_db),
               user: models.User = Depends(feed_user)):
    _check_collection(cid)
    tenant = request.state.tenant
    if oid == threat_feed.identity_id(tenant.id):
        return _taxii({"objects": [threat_feed.identity(tenant)]})
    row = (db.query(models.ThreatIndicator)
           .filter(models.ThreatIndicator.tenant_id == tenant.id, models.ThreatIndicator.stix_id == oid).first())
    if not row:
        raise HTTPException(status_code=404, detail="Unknown object")
    return _taxii({"objects": [threat_feed.to_stix(tenant, row)]})


# ------------------------------------------------------------------ downloads
@router.get("/api/threat-feed")
def feed_summary(request: Request, db: Session = Depends(get_db), user: models.User = Depends(feed_user)):
    base = settings.APP_URL.rstrip("/")
    return {**threat_feed.summary(db, user.tenant_id),
            "taxii": {"discovery": base + "/taxii2/", "api_root": _root(),
                      "collection_id": threat_feed.COLLECTION_ID},
            "downloads": {"stix": base + "/api/threat-feed/stix.json", "csv": base + "/api/threat-feed/indicators.csv",
                          "domains": base + "/api/threat-feed/domains.txt", "urls": base + "/api/threat-feed/urls.txt"}}


@router.get("/api/threat-feed/stix.json")
def stix_download(request: Request, min_confidence: int = Query(0, ge=0, le=100), db: Session = Depends(get_db),
                  user: models.User = Depends(feed_user)):
    rows = threat_feed.active(db, user.tenant_id, min_confidence=min_confidence)
    return JSONResponse(threat_feed.bundle(request.state.tenant, rows), media_type="application/stix+json;version=2.1",
                        headers={"Content-Disposition": 'attachment; filename="phishlens-indicators.json"'})


@router.get("/api/threat-feed/indicators.csv")
def csv_download(min_confidence: int = Query(0, ge=0, le=100), db: Session = Depends(get_db),
                 user: models.User = Depends(feed_user)):
    rows = threat_feed.active(db, user.tenant_id, min_confidence=min_confidence)
    return Response(threat_feed.csv_text(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="phishlens-indicators.csv"'})


@router.get("/api/threat-feed/{kind}.txt")
def list_download(kind: str, min_confidence: int = Query(0, ge=0, le=100), db: Session = Depends(get_db),
                  user: models.User = Depends(feed_user)):
    kinds = {"domains": "domain", "urls": "url", "emails": "email"}
    if kind not in kinds:
        raise HTTPException(status_code=404, detail="Use domains.txt, urls.txt or emails.txt")
    rows = threat_feed.active(db, user.tenant_id, kinds[kind], min_confidence)
    return PlainTextResponse(threat_feed.plain_list(rows))
