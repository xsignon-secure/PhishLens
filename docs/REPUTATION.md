# Reputation at Gmail and Outlook

Dashboard → **Reputation at Gmail and Outlook** shows how the two biggest
mailbox providers rate your mail, refreshed daily with the scheduled jobs
(or **Refresh now**). Owners and admins get an email, and the domain's
monitor an alert, when:

- Gmail rates a domain's reputation **Low** or **Bad**;
- Gmail users report **0.3%** or more of its mail as spam (Gmail's limit for
  bulk senders);
- Outlook.com marks a mail server IP **red** or blocks it.

Each problem alerts once; if it clears and comes back, it alerts again.

## Google Postmaster Tools

Each company connects its own Google account (read-only scope
`postmaster.readonly`). Postmaster only has data for domains verified at
[postmaster.google.com](https://postmaster.google.com) that send Gmail enough
mail (roughly 100+ messages a day).

The server needs one Google OAuth client, set up once by whoever runs it:

1. Google Cloud console → new project → **APIs & Services → Library** →
   enable **Gmail Postmaster Tools API**.
2. **OAuth consent screen**: External, add the scope
   `.../auth/postmaster.readonly`. Publish it (or add test users).
3. **Credentials → Create credentials → OAuth client ID** → *Web
   application*, authorized redirect URI
   `https://YOUR-APP-URL/reputation/google/callback`.
4. Set `GOOGLE_POSTMASTER_CLIENT_ID` and `GOOGLE_POSTMASTER_CLIENT_SECRET`
   and redeploy.

The refresh token is stored encrypted; **Disconnect Google** revokes it.

## Microsoft SNDS

1. Sign in at [sendersupport.olc.protection.outlook.com/snds](https://sendersupport.olc.protection.outlook.com/snds/)
   and request access for your mail servers' IP addresses.
2. **Automated Access** → enable it and copy the key.
3. Paste the key in the dashboard (asks for your authenticator code). It is
   stored encrypted. Save an empty key to disconnect.

SNDS reports per IP, so it suits companies that run their own mail servers or
dedicated sending IPs; shared IPs (Microsoft 365, Google Workspace) are
covered by the providers themselves.
