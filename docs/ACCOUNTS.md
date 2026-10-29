# Accounts, companies and sign-in

PhishLens has no self-signup and no invitation links. Accounts are created by
admins, and login details are emailed from each company's own mail server.

## Who does what

| Who | Signs in with | Can |
|---|---|---|
| Platform admin (whoever runs the server) | `ADMIN_PASSWORD` at `/platform` | Create companies and their owners, add an owner, send an owner new login details, suspend or reactivate a company. It sees company names and people only, never domains, scans or reports. |
| Owner | Email, password, authenticator app | Everything in their company: create admins and members, settings, mail server. |
| Admin | Email, password, authenticator app | Create and manage members, company settings, mail server. Can't create admins or touch owners. |
| Member | Email, password (authenticator optional) | Use the dashboard: monitors, scans, reports. No settings and no user management. |

Each account belongs to one company. An email address can only be used once
on a server.

## First setup

1. Set `ADMIN_PASSWORD` (long and random) in the server environment and
   redeploy. Open `/platform` and sign in with it.
2. **New company** → company name and the owner's email. If the server has
   `SMTP_*` settings, the owner gets their login details by email. Otherwise
   the temporary password is shown once on screen for you to hand over.
3. The owner signs in at `/login` with the temporary password, chooses their
   own password, and sets up an authenticator app (required for owners and
   admins). They get 10 one-time recovery codes.
4. Dashboard → **Email server**: the owner connects the company's mail server
   (for example `smtp.office365.com`, port 587, STARTTLS, sending as
   `it-support@company.com`) and clicks **Send test**.
5. Dashboard → **Users**: create admins and members, one at a time or from a
   CSV (`email,name,role`). Each one gets an email from the company's server
   with the sign-in link and a temporary password.

Companies that existed before accounts came back keep their data. Give them
an owner from `/platform` (**Add owner**).

## Temporary passwords

- Random, 16 characters, stored only as a hash.
- Work once, for `TEMP_PASSWORD_HOURS` (default 72), and only to choose a real
  password. Nothing else in the app is reachable before that.
- **New login details** (or **Reactivate**) makes a new one. The previous one
  stops working at once, and every session of that user ends. The old
  password is never sent again.
- A forgotten password works the same way: an admin sends new login details.
  There is no self-service reset, so nobody can find out from the login page
  whether an address has an account.
- If the email can't be sent, the account still exists. The Users table shows
  "Login email failed" with the mail server's answer. Fix the server and send
  new login details.
- Each company can send `CREDENTIAL_EMAILS_PER_HOUR` (default 50) login emails
  per hour.

## The company mail server

- The SMTP password is encrypted at rest and write-only: no page or API returns
  it. Leaving the field blank keeps it, but only while the server and username
  stay the same, so a changed host never receives the saved password.
- Only public addresses are accepted, and the address is resolved once and
  pinned for the connection, so the setting can't be pointed at internal
  services. Ports 587, 465, 2525 and 25.
- Login details, monitor alerts and scheduled reports for that company all go
  out through it. Without one, the server-wide `SMTP_*` settings are used.
- A sending job carries its company, and only that company's server is read
  for it.

## Sign-in and sessions

- Passwords: Argon2id, at least 12 characters, common and breached passwords
  refused (Have I Been Pwned range check, where only 5 characters of the
  SHA-1 hash leave the server; turn off with `PASSWORD_BREACH_CHECK=false`).
- Login gives the same "Invalid email or password" for an unknown email, a
  wrong password, a locked account and a suspended account, and takes the same
  time. Five failures lock the account for 15 minutes, doubling with each
  further failure (up to a day). Rate limits: 5 tries per account and 15 per
  IP address in 15 minutes.
- Sessions: a 15-minute access token and a rotating refresh token, both in
  httpOnly, SameSite=Lax cookies (Secure on https). A session ends after
  `SESSION_IDLE_MINUTES` (120) idle or `SESSION_MAX_HOURS` (12). A refresh token
  used again after rotation ends the session and is logged as critical.
- Security panel: see where you're signed in, sign out one device or all
  others, change your password (other devices are signed out), and manage the
  authenticator app and recovery codes.
- Role change, suspension, new login details, authenticator reset and
  deletion end that user's sessions at once. Suspending a company ends every
  session in it. API keys stop working when the user who made them is
  suspended or deleted.
- Step-up: creating, changing or deleting users, the mail server settings,
  API keys and data export need an authenticator code from the last 10
  minutes. The dashboard asks for it when needed. API keys can't do these at
  all.

## Threat model

| Attack | What stops it |
|---|---|
| Reading another company's data by changing an id in a URL (IDOR) | Every query filters on the signed-in user's company; another company's object is "not found" (404), never "forbidden". Tests in `tests/test_accounts.py` and `tests/test_security.py`. |
| Editing the company in a session token | Tokens are signed; a token with a bad signature is refused (403) and logged as `security.token_tampered`, critical. A validly signed token whose company doesn't match the account is refused, its session ended, and logged as `security.cross_tenant`. |
| Finding out who has an account | One login error for every failure, constant-time hashing for unknown emails, no signup or password-reset form. |
| Password guessing | Account lock with growing delay, per-account and per-IP limits, Argon2id, breached-password check. |
| Stolen session cookie | httpOnly cookies, short access tokens, idle and absolute expiry, refresh rotation with replay detection, per-device sign-out. Sensitive changes need a fresh authenticator code. |
| Stolen password | Authenticator app required for owners and admins (codes can't be reused); recovery codes stored as hashes. |
| Leaked or forwarded welcome email | Temporary password works once, expires, and must be replaced before anything else; "resend" invalidates it. |
| Mail server password theft | Encrypted at rest, never returned by any API, dropped when the host changes. |
| Using the mail server setting to reach internal hosts (SSRF) | Public addresses only, resolved once and pinned. |
| One company's emails sent through another's server | Sending jobs carry their company and read only its server (tested). |
| Admin escalating to owner | Owners are created only by the platform admin; admins manage members only. |
| CSRF | Double-submit token on cookie-authenticated changes, SameSite cookies. |

Not built, and why:

- **PostgreSQL row-level security.** Shared report links, the scheduled
  rescans and report imports read across companies by design, and Render's
  database user owns the tables (owners bypass RLS unless forced). Isolation
  is enforced in the query layer and covered by tests instead.
- **One person in several companies.** Each account belongs to one company,
  so there's no company switcher. Use a separate email per company.
- **Subdomains or custom domains per company.** All companies sign in at the
  same `/login`.

## Manual penetration-test checklist

Sign-in
- [ ] Unknown email, wrong password, suspended account: identical message.
- [ ] Sixth wrong password: still refused with the right password; unlocks later.
- [ ] Temporary password: second use fails; after expiry fails with "expired".
- [ ] `step_token` from login can't call any other API.
- [ ] Authenticator code reused within its 30 seconds: refused.
- [ ] Recovery code works once.

Sessions
- [ ] Copy the `refresh_token` cookie, wait a minute, use the copy: the
  session ends and a critical audit event appears.
- [ ] Change a user's role: their open browser is signed out.
- [ ] Suspend the company at `/platform`: every user is signed out.

Company isolation
- [ ] As company A, request company B's monitor, scan, user ids: 404.
- [ ] Edit `tid` in an access token (any key): 403 and a critical audit event.
- [ ] Shared report link without "share": 404.

Provisioning
- [ ] Member calls `POST /api/users`: 403. Admin creates an admin: 403.
- [ ] Admin suspends an owner or another admin: 403.
- [ ] Without a fresh code, `POST /api/users` answers `step_up_required`.
- [ ] `GET /api/team/smtp` never contains the SMTP password.
- [ ] Mail server set to `localhost`, `10.0.0.1` or a name resolving to a
  private address: refused.
- [ ] CSV with bad rows: good rows created, bad rows reported.
