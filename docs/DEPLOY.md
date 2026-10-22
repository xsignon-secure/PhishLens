# PhishLens — Production Deploy Checklist

Target: $0/month. Pick one path, then work the checklist top to bottom.

## Path A — Fly.io / Render (easiest)

> Render: follow `docs/DEPLOY-RENDER.md`. The `render.yaml` Blueprint sets up the app and Postgres for you.

1. `fly launch` (or Render dashboard → New Web Service from this repo).
   Dockerfile is included; nothing to change.
2. Set secrets (never in the repo):
   - `SECRET_KEY` — generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`
   - `DATABASE_URL` — free Postgres (Supabase/Neon/Supabase free tier);
     SQLite works but won't survive restarts on most free tiers.
   - `APP_URL` — your public URL (used in alert emails).
   - `SMTP_*` — optional; without it, alerts stay dashboard-only.
   - Leave `STRIPE_*` empty (billing intentionally unwired).
3. Deploy. Hit `/api/health` → `{"ok":true}`.
4. Create the first tenant at `/signup`.

## Path B — Single VPS (Oracle Cloud free tier)

1. Provision VM, point DNS A-record at it.
2. Install Python 3.12, clone repo, `pip install -r requirements.txt`.
3. systemd unit running `uvicorn app.main:app --host 127.0.0.1 --port 8000`.
4. Caddy as reverse proxy with automatic TLS:
   `yourdomain.com { reverse_proxy 127.0.0.1:8000 }`
5. Same env vars as Path A.

## Scheduled rescans (both paths)

Weekly, Monday 06:00 UTC:

```
0 6 * * 1  cd /srv/phishlens && .venv/bin/python scripts/rescan.py >> /var/log/phishlens-rescan.log 2>&1
```

On Fly.io/Render use their scheduled-job feature with the same command.
The worker skips monitors checked in the last 20h (`--force` overrides).

## Pre-launch verification

- [ ] `pytest tests/ -q` → all green
- [ ] Public scan of your own domain returns a sane score
- [ ] Signup → add monitor → rescan → alert row appears
- [ ] Share link works signed-out; unshare revokes it
- [ ] With SMTP set: trigger a score drop, confirm the email arrives
- [ ] `curl -sI https://yourdomain/` shows `strict-transport-security`
- [ ] DB backups: daily `pg_dump` (or copy the SQLite file) off the box

## Ongoing

- Watch `/var/log/phishlens-rescan.log` the first two Mondays.
- PhishLens has no plans or paywalls. On a public instance, use
  `MAX_MONITORS_PER_TEAM` and `SCAN_RATE_LIMIT_PER_HOUR` as abuse brakes.
