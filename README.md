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

Market comparison and what's still missing: `docs/MARKET-ANALYSIS-2026-10.md`.

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
| DNSSEC | 5 | DNS blocklists 5 (4 IP lists + Spamhaus DBL/SURBL for the domain) · CAA 5 |
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

## Monetization hooks (ready to wire)

- Free plan: 3 monitors, 50-scan history (enforced in code).
- `plan` column on tenants + Stripe keys in `.env.example` — add checkout +
  webhook to flip `free` → `pro` when you're ready (Stripe costs $0 until
  you're paid).

## Market position

See `docs/MARKET-ANALYSIS-2026-10.md` (EasyDMARC, MXToolbox, PowerDMARC,
dmarcian, Valimail, Red Sift, DMARC Report, Postmark). PhishLens covers the
mid-market essentials (scan, fix records, DMARC report analysis, monitoring,
chat/SIEM alerts, API) and adds built-in lookalike-domain alerts and free
header/domain tools. Still missing: hosted SPF/DMARC/MTA-STS, RUF reports,
SSO, MSP white-label, and wired billing.
