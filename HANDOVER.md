# PhishLens — Handover to XSignOn Corporation

**Date:** 2026-10-09
**What:** Complete, tested, market-ready multi-tenant SaaS — deterministic
email-security domain scanner.
**Repo:** this directory (git-initialized, clean commit `773dda9`).

## What it does

Enter a domain → 13 security checks in one pass → 0–100 score + grade →
shareable report → exact DNS records to publish for every failing check.
No AI, no external APIs, ~zero marginal cost per scan.

Checks: SPF · DKIM (selector auto-detection + key-strength) · DMARC · BIMI ·
MTA-STS · TLS-RPT · MX · SMTP STARTTLS · DNS blocklists · DNSSEC ·
CAA · TLS certificate · web security headers.

## Run it (5 minutes)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env        # set SECRET_KEY to a long random string
.venv/bin/uvicorn app.main:app --port 8000
# open http://localhost:8000
```

Tests: `.venv/bin/python -m pytest tests/ -q` (88 tests, all passing; they run against a throwaway database, never `phishlens.db`).

## Deploy it ($0)

- `Dockerfile` included → Fly.io / Render free tier.
- Set `SECRET_KEY` and `DATABASE_URL` (Supabase/Neon free Postgres for prod;
  SQLite is the default and fine for launch).
- Point a domain at it; Caddy or the platform handles TLS.

## Business model (ready to wire)

- Free: 3 monitored domains, 50-scan history (enforced in code).
- Paid: monitoring, drift alerts, reports, multi-domain (`plan` column on
  tenants; Stripe keys stubbed in `.env.example`). Stripe costs $0 until
  the first paying customer.
- Suggested: **free scan as lead-gen for XSignOn's enterprise MFA sales**
  (see `STRATEGIC-FIT.md`).

## What's stubbed / not yet built

- Stripe checkout + webhook (env keys ready, no code yet).
- Scheduled weekly rescans (cron hitting `POST /api/monitors/{id}/rescan`).
- Email alerts / PDF reports.

## Security model

bcrypt passwords · JWT sessions · tenant isolation enforced + tested ·
rate-limited public scanner · SSRF guard (won't scan private/internal targets) ·
strict domain validation · opt-in shareable report links.

## IP

All code, docs, and assets in this repo are assigned to XSignOn Corporation
per the signed IP Assignment Agreement (see `IP-ASSIGNMENT.md` template —
have counsel review before signing).
