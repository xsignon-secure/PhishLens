# PhishLens

Deterministic email-security scanner — multi-tenant SaaS. One scan grades a
domain across **13 checks** (SPF, DKIM with selector auto-detection + true key-strength
validation, DMARC, BIMI, MTA-STS, TLS-RPT, MX, SMTP STARTTLS, DNS blocklists,
DNSSEC, TLS certificate, web security headers), scores 0–100, and returns the
**exact DNS records to publish** for every failing check.

No AI. No external APIs. No tracking. Pure DNS + HTTPS lookups, so the marginal
cost per scan is ~zero.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env   # then set SECRET_KEY
.venv/bin/uvicorn app.main:app --port 8000
# open http://localhost:8000
```

Run tests: `.venv/bin/python -m pytest tests/ -q`

## Architecture

```
app/
  main.py            FastAPI app, security headers, routers
  config.py          env-based settings
  database.py        SQLAlchemy (SQLite dev / Postgres via DATABASE_URL)
  models.py          Tenant, User, Scan, Monitor, Alert
  schemas.py         Pydantic I/O schemas
  security.py        bcrypt passwords, JWT sessions
  deps.py            auth, tenant scoping, rate limits, domain validation, SSRF guard
  scanner/
    dns_checks.py    SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI / MX / SMTP TLS / DNSBL / DNSSEC
    web_checks.py    TLS cert, security headers
    scoring.py       weighted 0-100, grades, prioritized action plan
    engine.py        orchestration + persistence
  routers/
    auth.py          signup (creates tenant+owner), login, logout, me
    scans.py         public scan, tenant scans, share/unshare report links
    monitors.py      watch domains, rescan, drift alerts
    pages.py         landing, login, signup, dashboard, shared report
  templates/ + static/   server-rendered UI, vanilla JS (no build step)
```

## DMARC reports, lookalikes, header check

- **DMARC aggregate reports**: upload .xml/.gz/.zip reports in the dashboard,
  POST them to `/api/dmarc/reports` (raw body, API key or session), or run
  `scripts/fetch_dmarc_reports.py` hourly against a shared report mailbox
  (`DMARC_IMAP_HOST`, `DMARC_IMAP_USER`, `DMARC_IMAP_PASSWORD`; reports are filed
  for every tenant monitoring the domain). `GET /api/dmarc/summary/{domain}`
  groups traffic by sending service, gives pass rates and a fix per failing
  sender, and says when it's safe to move to quarantine/reject.
- **Lookalike domains**: `POST /api/tools/lookalikes` (signed in, 10/hour per
  tenant) checks several hundred typo / homoglyph / keyword / TLD variants and
  ranks registered ones by risk (mail servers = high). `scripts/rescan.py`
  rechecks monitored domains weekly (`--lookalike-days`) and alerts on new
  registrations.
- **Email header analyzer**: `/tools/headers` (public, nothing stored) reads
  SPF/DKIM/DMARC verdicts and flags Reply-To redirection, fake display-name
  addresses and punycode senders.
- **Chat alerts**: a Slack, Microsoft Teams or Discord webhook URL gets a
  readable message instead of the signed JSON event.

- **Forensic (RUF) reports**: failure reports (ARF) are read from the same
  mailbox or uploaded as .eml; only headers are kept, never message bodies.
- **Hosted DMARC / SPF / MTA-STS** with SPF flattening: `docs/HOSTED-RECORDS.md`.
- **One-click fixes**: connect a Cloudflare API token and publish fix records
  from the report.
- **SSO** (OpenID Connect, optional enforcement): `docs/SSO.md`.
- **Billing**: Stripe Checkout + Customer Portal, plan set only by the signed
  webhook: `docs/BILLING.md`. Without Stripe keys everything is unlocked.
- **White-label (MSPs)**: brand name, colour, logo and footer on shared
  reports, PDFs and alert emails; client tags on monitors; extra alert
  recipients such as a PSA's email-to-ticket inbox.

Market comparison: `docs/MARKET-ANALYSIS-2026-10.md`.

## Reports

- **PDF export**: every report has a "Download PDF" button (dashboard, shared
  link, and the landing-page scan). Branded, one page for most domains, ready
  to attach to an email. Rendered with reportlab, no system dependencies.
- **Score history**: signed-in scans and monitors show a sparkline of past
  scores and "your score went from X to Y since <date>" (compared with the
  newest scan at least 30 days old, else the oldest one).
  `GET /api/scans/history/{domain}` returns the same data.
- **VirusTotal reputation badge** (optional): set `VIRUSTOTAL_API_KEY` to show
  "flagged by X/N vendors" with a link to the VirusTotal report. Informational
  only, never part of the score; cached per domain and kept within the free
  tier's 4 lookups/minute. **The free/public VirusTotal key is licensed for
  non-commercial use only: get a premium key before shipping this.**

## Multi-tenancy & security model

- Every tenant-owned row carries `tenant_id`; all queries filter on it via
  `tenant_*()` helpers in `deps.py`. Covered by `tests/test_security.py`
  (cross-tenant read/update/delete all return 404).
- Passwords: bcrypt(12). Sessions: short-lived JWT (Bearer or httpOnly cookie).
- Public scan endpoint is rate-limited per IP (default 20/hour); login, MFA,
  signup, password-reset and verification endpoints have brute-force limits.
  Limits are in-process: behind a proxy run uvicorn with `--proxy-headers`
  (the Dockerfile does), and move to Redis before running multiple workers.
- Input hardening: strict domain validation (IDNA, no IP literals, no
  `.local`/`.internal`/`.onion`), plus an SSRF guard that refuses targets
  resolving to non-public addresses. The same guard covers every outbound hop
  the scanner makes (HTTP redirects, MTA-STS policy host, BIMI logo URL, MX
  hosts) and webhook deliveries.
- Shareable reports are opt-in (`is_public`) with unguessable IDs; unshare
  revokes the link.

## Scoring (100 points)

| Check | Max | Notes |
|---|---|---|
| DMARC | 20 | reject=20, quarantine=12, none=5; −3 if pct<100, −2 if no rua |
| SPF | 15 | −all=15, ~all=11; fail on >10 lookups or +all |
| DKIM | 15 | 2048-bit+=15, 1024=8; selector auto-detection |
| MTA-STS | 10 | enforce=10, testing=4 |
| MX | 5 | SMTP STARTTLS 5 |
| TLS-RPT | 3 | BIMI 2 |
| DNSSEC | 5 | DNS blocklists 5 (7 IP lists + Spamhaus DBL, SURBL, URIBL for the domain) · CAA 5 |
| TLS cert | 5 | Web security headers 5 |

## Database

SQLite by default (`phishlens.db`); Postgres for production via `DATABASE_URL`.
Schema changes go through Alembic — see `docs/ENTERPRISE.md` for the workflow
(`alembic revision --autogenerate`, `alembic upgrade head` on deploy).

## Deployment ($0 options)

- **Fly.io / Render free tier**: `Dockerfile` included; set `SECRET_KEY` and
  `DATABASE_URL` (Supabase/Neon free Postgres for production).
- **Single VPS (Oracle Cloud free tier)**: systemd + uvicorn, SQLite is fine
  to start; Caddy for TLS.
- Full checklist: `docs/DEPLOY.md`.
- **Scheduled rescans**: `scripts/rescan.py` (weekly cron) rescans every
  active monitor, records drift alerts, and emails tenant owners.
- **Email alerts**: stdlib SMTP, configured via `SMTP_*` in `.env`; when
  unconfigured, alerts stay dashboard-only and nothing breaks.

## Plans

- Free: 3 monitored domains, 50-scan history.
- Pro (Stripe subscription): 100 domains, hosted records, one-click fixes,
  SSO, white-label, extra alert recipients. See `docs/BILLING.md`.

## Market position

See `docs/MARKET-ANALYSIS-2026-10.md` (EasyDMARC, MXToolbox, PowerDMARC,
dmarcian, Valimail, Red Sift, DMARC Report, Postmark). PhishLens covers the
mid-market essentials (scan, fix records, DMARC report analysis, monitoring,
chat/SIEM alerts, API) and adds built-in lookalike-domain alerts and free
header/domain tools, plus hosted records, SSO, white-label and billing.
