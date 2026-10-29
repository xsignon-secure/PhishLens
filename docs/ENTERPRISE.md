# PhishLens — Enterprise Readiness

## Shipped (verifiable in code + tests)

**Access**
- No user accounts: one `ADMIN_PASSWORD` set on the server opens the dashboard;
  changing it (or **Sign out everywhere**) revokes every session
- Short-lived JWT sessions (Bearer or httpOnly cookie), login brute-force limit
- Double-submit CSRF protection on cookie-authenticated mutations;
  Bearer/API-key auth explicitly exempt
- `Secure` cookie flag auto-enabled on https

**Integrations**
- API keys (`plk_…`, sha256-hashed at rest, shown once, revocable,
  last-used tracking) via `X-API-Key`
- Signed alert webhooks (HMAC-SHA256 `X-PhishLens-Signature`) for SIEM ingestion,
  with dashboard configuration + test delivery

**Observability & audit**
- Append-only audit log (logins and failed logins, scans, monitors, shares,
  key/webhook changes, exports) with IP
- Structured logs with request IDs (`X-Request-ID` echoed on responses)
- `/api/health` for load-balancer checks

**Data**
- Alembic migrations (`alembic upgrade head` on deploy)
- Data export (JSON) for portability/GDPR-style requests
- SQLite for dev, Postgres for production via `DATABASE_URL`

## Roadmap (organizational / later engineering)

| Item | Notes |
|---|---|
| SOC 2 Type II | Organizational: auditor, 6–12 month observation window. The audit log, access controls, and change discipline here are the technical foundation. |
| Status page | Wire `/api/health` into an external uptime monitor. |
| Penetration test | Annual, before enterprise deals; scope the API + auth flows. |
| Data residency | Postgres per-region; `DATABASE_URL` already makes this a deploy choice. |
| Rate limits per plan | In-memory limiter now; move to Redis when multi-worker. |

## Migration workflow

```bash
# after changing app/models.py:
.venv/bin/alembic revision --autogenerate -m "describe change"
# review alembic/versions/<rev>_<name>.py, then:
.venv/bin/alembic upgrade head
```

Production deploys run `alembic upgrade head` before starting the app.
Development keeps the startup `create_all` for zero-friction local runs.
