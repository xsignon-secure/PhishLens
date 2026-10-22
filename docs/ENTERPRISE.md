# PhishLens — Enterprise Readiness

## Shipped (verifiable in code + tests)

**Identity & access**
- bcrypt(12) passwords, short-lived JWT sessions (Bearer or httpOnly cookie)
- TOTP MFA (authenticator apps) with setup/verify/disable + MFA login challenge
- Email verification, password reset (single-use, expiring tokens)
- Team invitations (owner invites member; invite links expire in 72h)
- Double-submit CSRF protection on cookie-authenticated mutations;
  Bearer/API-key auth explicitly exempt
- `Secure` cookie flag auto-enabled on https

**Multi-tenancy**
- `tenant_id` on every tenant-owned row; all access filtered through it
- Cross-tenant read/update/delete covered by automated tests (all return 404)
- Owner/member roles; destructive/admin actions are owner-only

**Integrations**
- Tenant API keys (`plk_…`, sha256-hashed at rest, shown once, revocable,
  last-used tracking) via `X-API-Key`
- Signed alert webhooks (HMAC-SHA256 `X-PhishLens-Signature`) for SIEM ingestion,
  with dashboard configuration + test delivery

**Observability & audit**
- Append-only audit log (logins, MFA events, scans, monitors, shares,
  key/invite/webhook changes, exports) with IP + owner-only viewer
- Structured logs with request IDs (`X-Request-ID` echoed on responses)
- `/api/health` for load-balancer checks

**Data**
- Alembic migrations (`alembic upgrade head` on deploy)
- Tenant data export (JSON, owner-only) for portability/GDPR-style requests
- SQLite for dev, Postgres for production via `DATABASE_URL`

## Roadmap (organizational / later engineering)

| Item | Notes |
|---|---|
| SSO (SAML/OIDC) | Biggest enterprise ask. Interface point is `get_current_user` in `app/deps.py`; add an OIDC provider config + JIT provisioning when a customer requires it. |
| SCIM provisioning | Follows SSO; needs a customer pilot to spec correctly. |
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
