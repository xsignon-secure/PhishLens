"""PhishLens as an MCP server (Model Context Protocol, streamable HTTP
transport, JSON responses only). AI assistants such as Claude connect to
<APP_URL>/mcp with a team API key as a Bearer token, then scan domains and
read reports, monitors, alerts and DMARC data. See docs/MCP.md."""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .. import audit, dmarc_reports, models, plans
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, normalize_domain, rate_limit, tenant_monitors
from ..scanner import engine

router = APIRouter(tags=["mcp"])
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

_DOMAIN = {"type": "object", "properties": {"domain": {"type": "string", "description": "Domain, e.g. example.com"}},
           "required": ["domain"]}
TOOLS = [
    {"name": "scan_domain", "description": "Scan a domain's email security now (SPF, DKIM, DMARC, MTA-STS, "
     "TLS-RPT, BIMI, DNSSEC, blocklists, TLS...). Returns the score, grade and every failing check with its fix. "
     "Saved to the team's history.", "inputSchema": _DOMAIN},
    {"name": "get_latest_report", "description": "The team's most recent scan report for a domain, without rescanning.",
     "inputSchema": _DOMAIN},
    {"name": "list_monitors", "description": "Domains the team monitors, with client label, last score and alert level.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_alerts", "description": "The team's most recent monitor alerts (score drops, failing checks, "
     "DNS record changes, lookalike domains).",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}}}},
    {"name": "dmarc_summary", "description": "DMARC aggregate report summary for a domain: senders, pass rates, "
     "fixes, and whether it is safe to move to quarantine or reject.",
     "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"},
                                                       "days": {"type": "integer", "minimum": 1, "maximum": 365}},
                     "required": ["domain"]}},
    {"name": "dns_changes", "description": "Email-security DNS record changes seen for a monitored domain, newest first.",
     "inputSchema": _DOMAIN},
]


def _report(scan: models.Scan) -> dict:
    checks = (scan.result or {}).get("checks", [])
    return {
        "domain": scan.domain, "score": scan.score, "grade": scan.grade,
        "scanned_at": scan.created_at.isoformat() + "Z",
        "problems": [{"check": c.get("title"), "status": c.get("status"), "issues": c.get("issues", []),
                      "fixes": c.get("fixes", [])} for c in checks if c.get("status") in ("fail", "warn")],
        "passing": [c.get("title") for c in checks if c.get("status") == "pass"],
        "report_url": f"{settings.APP_URL.rstrip('/')}/dashboard",
    }


def _call(name: str, args: dict, request: Request, db: Session, user: models.User):
    if name == "scan_domain":
        rate_limit(request, f"mcp-scan:{user.tenant_id}", 60)
        scan = engine.run_scan(db, str(args.get("domain", "")), tenant_id=user.tenant_id)
        audit.log_request(db, request, "scan.create", user, {"domain": scan.domain, "score": scan.score, "via": "mcp"})
        return _report(scan)
    if name == "get_latest_report":
        domain = normalize_domain(str(args.get("domain", "")))
        scan = (db.query(models.Scan).filter(models.Scan.tenant_id == user.tenant_id, models.Scan.domain == domain)
                .order_by(models.Scan.created_at.desc()).first())
        return _report(scan) if scan else {"domain": domain, "error": "No scan yet. Use scan_domain."}
    if name == "list_monitors":
        return [{"domain": m.domain, "client": m.client, "last_score": m.last_score, "alert_level": m.alert_level,
                 "active": m.is_active,
                 "last_checked_at": m.last_checked_at.isoformat() + "Z" if m.last_checked_at else None}
                for m in tenant_monitors(db, user).order_by(models.Monitor.domain).all()]
    if name == "list_alerts":
        limit = max(1, min(int(args.get("limit") or 20), 100))
        rows = (db.query(models.Alert).filter(models.Alert.tenant_id == user.tenant_id)
                .order_by(models.Alert.created_at.desc()).limit(limit).all())
        return [{"kind": a.kind, "message": a.message, "at": a.created_at.isoformat() + "Z"} for a in rows]
    if name == "dmarc_summary":
        domain = normalize_domain(str(args.get("domain", "")))
        days = max(1, min(int(args.get("days") or 30), 365))
        reports = (db.query(models.DmarcReport)
                   .filter(models.DmarcReport.tenant_id == user.tenant_id, models.DmarcReport.domain == domain,
                           models.DmarcReport.date_begin >= datetime.utcnow() - timedelta(days=days)).all())
        s = dmarc_reports.summarize(reports, domain, days)
        for row in s["senders"]:
            row.pop("sample_ips", None)
        s.pop("ips", None)
        return s
    if name == "dns_changes":
        domain = normalize_domain(str(args.get("domain", "")))
        rows = (db.query(models.DnsChange)
                .filter(models.DnsChange.tenant_id == user.tenant_id, models.DnsChange.domain == domain)
                .order_by(models.DnsChange.created_at.desc()).limit(100).all())
        return [{"record": c.record, "old": c.old, "new": c.new, "at": c.created_at.isoformat() + "Z"} for c in rows]
    raise KeyError(name)


def _result(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _handle(msg: dict, request: Request, db: Session, user: models.User) -> dict | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid request")
    method, msg_id, params = msg["method"], msg.get("id"), msg.get("params") or {}
    if "id" not in msg:  # notification (e.g. notifications/initialized): nothing to answer
        return None
    if method == "initialize":
        wanted = params.get("protocolVersion")
        return _result(msg_id, {
            "protocolVersion": wanted if wanted in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "phishlens", "title": settings.APP_NAME, "version": "1.0"},
            "instructions": "Email security for the domains of this PhishLens team. Use scan_domain to check a "
                            "domain, get_latest_report to read the last result, and dmarc_summary for DMARC "
                            "report data. Every problem comes with the exact fix.",
        })
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if not isinstance(args, dict):
            return _error(msg_id, -32602, "arguments must be an object")
        try:
            data = _call(name, args, request, db, user)
        except KeyError:
            return _error(msg_id, -32602, f"Unknown tool: {name}")
        except HTTPException as exc:  # bad domain, rate limit...: a tool error the model can read
            return _result(msg_id, {"content": [{"type": "text", "text": str(exc.detail)}], "isError": True})
        except (TypeError, ValueError) as exc:
            return _result(msg_id, {"content": [{"type": "text", "text": f"Invalid arguments: {exc}"}], "isError": True})
        return _result(msg_id, {"content": [{"type": "text", "text": json.dumps(data, indent=1, default=str)}],
                                "structuredContent": data if isinstance(data, dict) else {"items": data},
                                "isError": False})
    return _error(msg_id, -32601, f"Method not found: {method}")


def _header_auth(request: Request) -> None:
    """MCP clients authenticate with a header. A browser session cookie alone
    is refused, so a hostile web page can't drive the endpoint as the signed-in
    user (cross-site POSTs carry cookies, not headers)."""
    if not request.headers.get("authorization") and not request.headers.get("x-api-key"):
        raise HTTPException(status_code=401, detail="Send a team API key: Authorization: Bearer plk_...",
                            headers={"WWW-Authenticate": "Bearer"})


@router.post("/mcp", dependencies=[Depends(_header_auth)])
async def mcp(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    plans.require(user.tenant, "mcp")
    rate_limit(request, f"mcp:{user.tenant_id}", 600)
    try:
        body = json.loads(await request.body())
    except ValueError:
        return JSONResponse(_error(None, -32700, "Parse error"), status_code=400)
    if isinstance(body, list):  # JSON-RPC batch (2025-03-26)
        out = [r for r in (_handle(m, request, db, user) for m in body) if r is not None]
        return JSONResponse(out) if out else Response(status_code=202)
    out = _handle(body, request, db, user)
    return JSONResponse(out) if out is not None else Response(status_code=202)


@router.get("/mcp")
def mcp_stream():
    # No server-initiated messages: no SSE stream to offer.
    return Response(status_code=405, headers={"Allow": "POST"})
