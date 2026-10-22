# Deploy PhishLens on Render

There are two ways to deploy:

- **Option A: from your laptop (no GitHub).** You build a Docker image on your
  laptop, push it to Docker Hub, and Render runs that image.
- **Option B: from a GitHub repo.** Render builds from `render.yaml` and
  redeploys on every push. See further below.

---

# Option A: deploy from your laptop

About 20 minutes the first time. You need:

- **Docker Desktop** installed and running (docker.com/products/docker-desktop).
- A free **Docker Hub** account (hub.docker.com). It holds your image, and a
  private repository keeps it non-public.
- A **Render** account (render.com).

## A1. Create a private repository on Docker Hub

hub.docker.com → **Create repository** → name `phishlens` → visibility
**Private** → **Create**.

Then create an access token for Render: your avatar → **Account settings** →
**Personal access tokens** → **Generate new token** → access **Read-only** →
copy the token and keep it for step A4.

## A2. Build and push the image from your laptop

In a terminal, inside the `phishlens` folder (replace `YOURNAME` with your
Docker Hub username):

```bash
docker login
docker buildx build --platform linux/amd64 -t YOURNAME/phishlens:latest --push .
```

`--platform linux/amd64` matters on Apple Silicon (M1–M4) Macs, because
Render's servers are amd64. `.dockerignore` keeps your `.env`, `.venv` and
`phishlens.db` out of the image, so your secrets stay on your laptop.

## A3. Create the database on Render

dashboard.render.com → **New** → **Postgres**

- Name: `phishlens-db`
- Region: pick one, and use the **same region** for the web service in step A5.
- Plan: **Free** (it expires after a trial period; for a database that stays free, use Neon or Supabase and paste its URL as `DATABASE_URL`).

Click **Create Database**. When it is ready, copy its **Internal Database URL**
(on the database page under **Connections**).

## A4. Give Render access to your private image

Render dashboard → your avatar → **Account Settings** (or **Workspace
Settings**) → **Container Registry Credentials** → **Add**:

- Registry: **Docker Hub**
- Username: your Docker Hub username
- Password: the access token from step A1

## A5. Create the web service

**New** → **Web Service** → **Existing Image**:

- Image URL: `docker.io/YOURNAME/phishlens:latest`
- Credentials: the Docker Hub credential from step A4
- Name `phishlens`, the **same region** as the database, instance type **Free**

Under **Environment Variables** add:

| Key | Value |
|---|---|
| `DATABASE_URL` | the Internal Database URL from step A3 |
| `SECRET_KEY` | click **Generate** (or paste a long random string) |
| `VIRUSTOTAL_API_KEY` | your VirusTotal key (optional) |

Under **Advanced**, set **Health Check Path** to `/api/health`. Then click
**Deploy Web Service**.

## A6. Check it is live

Under **Logs** you should see `Running upgrade -> 7af353fb1c9a` and then
`Uvicorn running on http://0.0.0.0:10000`. When the status shows **Live**,
open `https://phishlens-xxxx.onrender.com/api/health` (it returns
`{"ok":true,...}`), then go to `/signup` to create your account.

## Updating later

After you change the code on your laptop:

```bash
docker buildx build --platform linux/amd64 -t YOURNAME/phishlens:latest --push .
```

Then, on the Render service: **Manual Deploy** → **Deploy latest reference**.
Database migrations run automatically on start.

Email (SMTP), a custom domain and the free-plan notes below apply to Option A
too. For weekly rescans, set `RESCAN_INTERVAL_HOURS=168` (step 7); no paid
cron job is needed.

---

# Option B: deploy from GitHub with the Blueprint

The repo already contains `render.yaml`, which creates the web app and Postgres
and wires them together.

## Step 1: Put the project on GitHub

Render deploys from a Git repository. In a terminal, inside the `phishlens` folder:

```bash
git init
git add .
git status          # check that .env, .venv and phishlens.db are NOT listed
git commit -m "PhishLens"
```

Then on github.com: **New repository** → name it `phishlens` → set it to
**Private** → **Create** (leave it empty, with no README). Copy the two
commands GitHub shows under "push an existing repository", for example:

```bash
git remote add origin https://github.com/<you>/phishlens.git
git branch -M main
git push -u origin main
```

> `.gitignore` keeps your `.env` (secrets) and the local `phishlens.db` out of
> GitHub. If `git status` lists either one, stop and fix that before you commit.

## Step 2: Create the Blueprint on Render

1. Open https://dashboard.render.com.
2. Click **New** → **Blueprint**.
3. Connect GitHub if asked, and pick your `phishlens` repo.
4. Render reads `render.yaml` and shows two resources: **phishlens** (web
   service) and **phishlens-db** (Postgres).
5. It asks for **VIRUSTOTAL_API_KEY**: paste your key, or leave it blank to
   turn the badge off.
6. Click **Apply** (or **Deploy Blueprint**).

## Step 3: Wait for the first deploy

Open the **phishlens** service → **Logs**. The first build takes a few minutes. You should see:

```
Running upgrade  -> 7af353fb1c9a, initial schema
Uvicorn running on http://0.0.0.0:10000
```

When the status turns **Live**, open the service URL
(`https://phishlens-xxxx.onrender.com`) and check `/api/health`, which
should return `{"ok":true,...}`.

## Step 4: Create your account

Go to `/signup` on your new URL and create the first owner account. Then work
through the checks in `docs/DEPLOY.md` → "Pre-launch verification": scan a
real domain, add a monitor, share a report, and download a PDF.

## Step 5 (optional): Email alerts and verification emails

Without SMTP, the app works and alerts show on the dashboard only. To send
email: **phishlens** service → **Environment** → add `SMTP_HOST`,
`SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (from your email
provider) → **Save**. Render redeploys automatically.

## Step 6 (optional): Your own domain

**phishlens** service → **Settings** → **Custom Domains** → add e.g.
`scan.example.com` and create the DNS record Render shows. Then set
`APP_URL=https://scan.example.com` under **Environment**, so links in emails
point to it.

## Step 7 (optional, free): Weekly rescans

The app rescans monitors by itself when `RESCAN_INTERVAL_HOURS` is set
(`render.yaml` sets 168, weekly). Free Render services sleep when idle, so
point a free uptime monitor (UptimeRobot, Better Stack, or the GitHub Actions
workflow `.github/workflows/keepalive.yml`) at `/api/health` to keep it awake.

---

## Good to know

- **Free plan limits** (check render.com/pricing, which changes):
  - Free web services sleep after about 15 idle minutes, so the first visit
    after that takes up to a minute.
  - The free Postgres database expires after a trial period: Neon or
    Supabase free Postgres don't, and work by pasting their URL as `DATABASE_URL`.
- **Updates:** every `git push` to `main` redeploys automatically. Database
  migrations run on each start.
- **Secrets:** `SECRET_KEY` is generated by Render. Never put secrets in
  `render.yaml` or commit `.env`.
- **VirusTotal:** a free VirusTotal account key works; its public API is for
  non-commercial use, which fits this free tool.
- **Backups:** paid Render Postgres plans include backups. On the free plan,
  export from the database page (**Connect** → use `pg_dump`) if you need a copy.
