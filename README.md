# PhishLens

[![CI](https://github.com/xsignon-secure/PhishLens/actions/workflows/ci.yml/badge.svg)](https://github.com/xsignon-secure/PhishLens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Free and open-source email-security scanner and DMARC monitor.** No paid
plans, no feature gates, no sign-up needed to scan. Self-host it in one
command or use a public instance.

One scan grades a
domain across **13 checks** (SPF, DKIM with selector auto-detection + true key-strength
validation, DMARC, BIMI, MTA-STS, TLS-RPT, MX, SMTP STARTTLS, DNS blocklists,
DNSSEC, TLS certificate, web security headers), scores 0–100, and returns the
**exact DNS records to publish** for every failing check. It also reports
DANE/TLSA, reverse DNS (PTR/FCrDNS), IPv6 and optional RPKI for your mail
servers, and validates BIMI certificates (VMC/CMC) and SVG Tiny PS logos.
DMARC checks follow the 2026 DMARC update (RFC 9989–9991: `t=`, `np=`, `psd=`;
`pct`, `rf`, `ri` flagged as obsolete).

No AI. No tracking. Scans are pure DNS + HTTPS lookups, so the marginal cost
per scan is ~zero. (The link checker also asks RDAP for a domain's age; Google
Safe Browsing, URLhaus, OpenPhish and VirusTotal lookups are opt-in.)

Everything is included for everyone: monitoring with drift alerts, DMARC
aggregate and forensic report analysis, SMTP TLS (TLS-RPT) report analysis,
report import from IMAP, Microsoft 365 or Gmail, lookalike-domain alerts, an
email header analyzer, PDF reports, Slack/Teams/Discord/SIEM alerts, a
Prometheus `/api/metrics` endpoint for Grafana, API keys, white-label reports, hosted DMARC/SPF/MTA-STS and one-click DNS fixes
on Cloudflare, DigitalOcean, deSEC, GoDaddy or Amazon Route 53.

Free tools, no account needed: `/tools` has a phishing link checker,
single-record checkers, record generators (DMARC, SPF, MTA-STS, TLS-RPT, BIMI)
and a DNS propagation checker. The app (public pages, dashboard and scan
report screens) is available in English, Spanish, French, German, Portuguese,
Hindi, Italian, Dutch and Japanese (machine-translated; corrections welcome). Scan findings and fix advice are still written in English.

| Scan report | Dashboard |
|---|---|
| ![Scan report with prioritized fixes](docs/screenshots/scan-report.png) | ![Dashboard with monitored domains](docs/screenshots/dashboard.png) |
| **Phishing link checker** | **Translated pages** |
| ![Phishing link checker](docs/screenshots/free-tools.png) | ![Landing page in Spanish](docs/screenshots/landing-es.png) |

## Run it with Docker (one command)

```bash
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") docker compose up -d
# open http://localhost:8000
```

`docker-compose.yml` runs PhishLens with Postgres and weekly built-in rescans.

## Run it with Python

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
    mail_checks.py   DANE / PTR (FCrDNS) / IPv6 / RPKI (informational, not scored)
    web_checks.py    TLS cert, security headers
    scoring.py       weighted 0-100, grades, prioritized action plan
    engine.py        orchestration + persistence
  routers/
    auth.py          login, first password, authenticator app, step-up, sessions
    users.py         admins create, suspend and remove company users
    platform.py      /platform: the server operator creates companies and owners
    scans.py         public scan, tenant scans, share/unshare report links
    monitors.py      watch domains, rescan, drift alerts
    pages.py         landing, login, dashboard, shared report
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
- **Send a test email**: signed in, `/tools/headers` gives you a one-off
  address; mail it from any service you send with and see SPF, DKIM, DMARC
  alignment and the delivery path as the receiving server recorded them. Needs
  `MAILTEST_ADDRESS` in the report mailbox (`docs/INTEGRATIONS.md`).
- **Guided setup**: `/setup` walks through domain, DMARC policy, publishing
  (hosted CNAME, TXT, or one click with a connected DNS provider) and alerts.
- **Alert levels and DNS timeline**: each monitor alerts at None, Essential
  (DMARC only), Balanced (failing checks, score drops, lookalikes) or
  Comprehensive (also any change to SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT,
  MX, NS or A records). Every change is kept in the monitor's "DNS changes"
  timeline (`GET /api/monitors/{id}/changes`) whatever the level.
- **SPF builder**: on `/tools`, a service picker adds the right include and a
  live meter shows DNS lookups against the limit of 10, with the include tree.
- **Chat alerts**: a Slack, Microsoft Teams or Discord webhook URL gets a
  readable message instead of the signed JSON event.

- **Forensic (RUF) reports**: failure reports (ARF) are read from the same
  mailbox or uploaded as .eml; only headers are kept, never message bodies.
  Paste your team's PGP public key and the sender, subject and auth details
  are encrypted to it (PhishLens keeps only the encrypted copy; needs `gpg`).
- **Hosted DMARC / SPF / MTA-STS / TLS-RPT / BIMI** with SPF flattening and
  BIMI logo hosting: `docs/HOSTED-RECORDS.md`.
- **DKIM key health**: from aggregate reports, every selector that signs for
  your domain with its service, volume, pass rate, last use and key length,
  flagging weak keys and keys unused for 90 days.
- **BIMI logo checker**: `/tools` validates an SVG against SVG Tiny PS and
  shows a phone and desktop inbox preview.
- **Domain Connect**: one-click publishing at hosts that support it, with no
  API token (`docs/DOMAIN-CONNECT.md`).
- **One-click fixes**: connect a Cloudflare API token and publish fix records
  from the report.
- **Admin-created accounts**: no signup and no invite links. The server
  operator creates each company and its owner at `/platform`; owners and
  admins create their users, and login details go out from the company's own
  mail server. Temporary passwords, a required authenticator app for owners
  and admins, and a fresh code for sensitive changes (`docs/ACCOUNTS.md`).
- **Hosted plans (optional)**: `PLANS_ENABLED=true` gives each company a Free,
  Pro or MSP plan set at `/platform`. Off by default, so a self-hosted copy has
  every feature (`docs/PLANS.md`).
- **SIEM and PSA**: monitor alerts as syslog (RFC 5424 over UDP, TCP or TLS)
  or to Splunk HEC, and a ticket per alerting domain in the free, open-source
  helpdesks Zammad or GLPI, or in ConnectWise Manage, HaloPSA or Autotask:
  `docs/INTEGRATIONS.md`.
- **MCP server**: connect Claude or any MCP client to `/mcp` with a team API
  key to scan domains and read reports, alerts and DMARC data: `docs/MCP.md`.
- **White-label (MSPs)**: brand name, colour, logo and footer on shared
  reports, PDFs and alert emails; client tags on monitors; extra alert
  recipients such as a PSA's email-to-ticket inbox.

Market comparison: `docs/MARKET-ANALYSIS-2026-10.md`.

## Reports

- **PDF export**: every report has a "Download PDF" button (dashboard, shared
  link, and the landing-page scan). Branded, one page for most domains, ready
  to attach to an email. Rendered with reportlab, no system dependencies.
  "Email me this report" sends the PDF to the signed-in user's own address
  (needs SMTP).
- **Scheduled reports**: a weekly or monthly email to the team's owners (and
  extra alert addresses) with the latest PDF for each monitored domain. Set it
  on the dashboard; it goes out with the scheduled rescan (needs SMTP).
- **DMARC report views**: senders, sending hosts (reverse DNS), countries
  (with `GEOIP_DB`) and a daily volume chart of passing and failing mail.
- **Overview** (`/overview`): every monitored domain at a glance for MSPs and
  larger teams: clients, average and lowest scores, domains added and removed
  this month, and the most frequent alerts.
- **Observations**: each report lists the problems as Risk, Severity, Impact
  and Fix, highest severity first, on screen and in the PDF.
- **Score history**: signed-in scans and monitors show a sparkline of past
  scores and "your score went from X to Y since <date>" (compared with the
  newest scan at least 30 days old, else the oldest one).
  `GET /api/scans/history/{domain}` returns the same data.
- **VirusTotal reputation badge** (optional): set `VIRUSTOTAL_API_KEY` to show
  "flagged by X/N vendors" with a link to the VirusTotal report. Informational
  only, never part of the score; cached per domain and kept within the free
  tier's 4 lookups/minute. Use your own free VirusTotal key (its public API is
  for non-commercial use, which fits this free tool).

## Security model

- Accounts are created by admins only: no signup, no invites, no
  self-service reset. `ADMIN_PASSWORD` opens `/platform`, where the server
  operator creates companies and owners; it can't see company data. Each
  company's data is isolated; another company's ids answer 404. Full details,
  threat model and a pen-test checklist: `docs/ACCOUNTS.md`.
- Passwords are Argon2id with a breached-password check; temporary passwords
  expire and must be changed at first sign-in. Owners and admins must use an
  authenticator app, and user, mail server, API key and export changes need
  a code from the last 10 minutes.
- Sessions: 15-minute JWT plus a rotating refresh token, both in httpOnly
  cookies; idle and absolute expiry; refresh replay ends the session. API
  keys (`X-API-Key`) for scripts.
- Public scan endpoint is rate-limited per IP (default 20/hour); logins
  have per-account and per-IP limits with account lockout, and failed
  attempts are in the audit log.
  Behind a proxy run uvicorn with `--proxy-headers` (the Dockerfile does).
  Limits are in-process by default; set `RATE_LIMIT_STORAGE=database` when
  running several workers or instances so they share one counter. The
  rescan and report-fetch jobs take a database lease, so only one instance
  runs them.
- Password changes, role changes, suspension and "Sign out other devices"
  revoke sessions at once. MFA codes can't be reused, and MFA secrets and
  company SMTP passwords are encrypted at rest.
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
| DMARC | 20 | reject=20, quarantine=12, none=5; −3 if t=y or legacy pct<100, −2 if no rua |
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

- **Prebuilt image**: every push to `main` publishes
  `ghcr.io/xsignon-secure/phishlens:latest` (plus version and commit tags).
- **Fly.io / Render free tier**: use the image above or the `Dockerfile`; set
  `SECRET_KEY` and `DATABASE_URL` (Neon or Supabase free Postgres; Render's
  free Postgres expires).
- **Report mailbox**: set `REPORT_FETCH_MINUTES=60` plus the IMAP, Microsoft
  Graph or Gmail variables in `.env.example` and the app imports DMARC and
  TLS-RPT reports by itself.
- **Optional**: `RPKI_CHECK=true` (asks RIPEstat), `GEOIP_DB=/path/GeoLite2-Country.mmdb`
  (adds country to DMARC senders; `pip install maxminddb`).
- **Link checker feeds** (optional): `SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`,
  `OPENPHISH_FEED=true`; `URL_CHECK_RDAP=false` turns off the domain-age lookup.
- **Single VPS (Oracle Cloud free tier)**: systemd + uvicorn, SQLite is fine
  to start; Caddy for TLS.
- Full checklist: `docs/DEPLOY.md`.
- **Scheduled rescans**: set `RESCAN_INTERVAL_HOURS=168` and the app rescans
  every active monitor weekly by itself, records drift alerts and emails
  owners; no cron service needed. Or run `scripts/rescan.py` from cron.
- **Public instances**: `MAX_MONITORS_PER_TEAM` (default 0 = unlimited) and
  `SCAN_RATE_LIMIT_PER_HOUR` are abuse brakes only; nothing is paywalled.
- **Email alerts**: stdlib SMTP, configured via `SMTP_*` in `.env`; when
  unconfigured, alerts stay dashboard-only and nothing breaks.

## Contributing

PhishLens is MIT-licensed and welcomes contributions: see
[CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
and [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.

## How it compares

See `docs/MARKET-ANALYSIS-2026-10.md` (EasyDMARC, MXToolbox, PowerDMARC,
dmarcian, Valimail, Red Sift, DMARC Report, Postmark). Those tools charge for
monitoring, DMARC reports, hosted records and white-label; PhishLens gives all
of it away under the MIT License and can be self-hosted.
