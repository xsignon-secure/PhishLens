# Report-phish button (Outlook and Gmail)

Staff click **Report phishing** on a suspicious email; it lands in the
dashboard's *Reported phishing* inbox with the same checks as an upload
(sender authentication, every link against the blocklists, optional AI
triage, takedown drafts for dangerous links). Only headers and links are
kept, never the message text.

## Create the files

Dashboard → *Reported phishing* → **Report-phish button for Outlook and
Gmail** → **Create the add-in files** (owners and admins; asks for your
authenticator code). Download the three files right away: they contain the
company's report key, which is stored hashed and shown only once.

Creating new files turns off the old key; **Turn off the button** revokes it.

The key can only *send* reports (`POST /api/report-button/report`). It can't
list or read reports, so a leaked key at worst lets someone add junk
reports, which are rate limited (300 per hour). The reporter's address comes
from the mail client and is shown as given.

## Outlook (Microsoft 365)

1. Microsoft 365 admin center → **Settings → Integrated apps → Upload custom
   apps** → *Office Add-in* → upload `phishlens-report-manifest.xml`.
2. Assign it to everyone (or a test group). It shows up in Outlook within a
   few hours, as a **Report phishing** button when reading a message.

Works in Outlook on the web, new Outlook for Windows, classic Outlook and
Outlook for Mac. Newer Outlook sends the whole message; older versions send
the headers and the HTML body.

The task pane is served from `APP_URL/addins/outlook/taskpane.html`, so
`APP_URL` must be the public **https** address of your server.

## Gmail (Google Workspace)

1. Open [script.google.com](https://script.google.com) → **New project**.
2. Paste `Code.gs`. In **Project settings**, tick *Show "appsscript.json"
   manifest file*, and replace its content with the downloaded
   `appsscript.json`.
3. **Deploy → Test deployments → Install** to try it yourself.
4. For everyone: link the script to a Google Cloud project, configure the
   Google Workspace Marketplace SDK as a private (internal) app, and install
   it for your domain from the Admin console.
