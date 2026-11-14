# Microsoft 365 and Google Workspace check

Dashboard → **Security** → *Microsoft 365 and Google Workspace check*.
Read-only checks of the settings that decide whether a phished password
becomes a breach. Rechecked weekly with the scheduled jobs, or **Check now**.

| Check | Microsoft 365 | Google Workspace |
|---|---|---|
| Everyone must use multi-factor sign-in | Security defaults or a Conditional Access policy for all users | 2-Step Verification enforced |
| How many users have MFA set up | Needs Entra ID P1/P2 (skipped otherwise) | ✓ |
| Legacy sign-in (no MFA possible) blocked | ✓ | n/a (Google turned it off) |
| 2 to 4 global / super admins | ✓ | ✓, plus super admins without 2SV |
| Users can't let any app read their mail (consent phishing) | ✓ | — |
| Mail forwarded outside the company | Inbox rules (first 100 users) | Automatic forwarding (first 100 users) |

Verified domains that PhishLens doesn't monitor yet are listed with a
one-click **+ domain** button.

## Microsoft 365 (server setup, once)

1. Entra admin center → **App registrations → New registration**: any name,
   *Accounts in any organizational directory (multitenant)*, redirect URI
   (Web) `https://YOUR-APP-URL/posture/m365/callback`.
2. **API permissions → Add → Microsoft Graph → Application permissions**:
   `Directory.Read.All`, `Policy.Read.All`, `MailboxSettings.Read`,
   `AuditLog.Read.All` (for MFA registration; optional).
3. **Certificates & secrets → New client secret**.
4. Set `M365_CLIENT_ID` (Application ID) and `M365_CLIENT_SECRET`, redeploy.

Customers then click **Connect Microsoft 365** and a Global Administrator
grants admin consent. PhishLens stores only their directory (tenant) id and
asks for a short-lived token at each check. To disconnect, also delete the
app under *Enterprise applications* in their tenant.

## Google Workspace (server setup, once)

1. Google Cloud console → project → enable **Admin SDK API** and **Gmail
   API**.
2. **IAM & Admin → Service accounts → Create**; *Keys → Add key → JSON*.
3. Set `GOOGLE_WORKSPACE_SERVICE_ACCOUNT` to the JSON content (or a file
   path), redeploy.

Customers open **Connect Google Workspace**: the dashboard shows the client
id and scopes to add in *Admin console → Security → Access and data control
→ API controls → Domain-wide delegation*, then they enter their domain and a
super admin's address. Scopes:

- `admin.directory.user.readonly`, `admin.directory.domain.readonly`: users,
  2SV status, admins, domains (impersonating the super admin);
- `gmail.settings.basic`: each user's automatic forwarding setting
  (impersonating each user). PhishLens only reads; there is no narrower
  Google scope for forwarding settings, and it gives no access to mail.

Remove the delegation entry to disconnect.
