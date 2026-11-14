# Phishing simulations

Send staff a harmless practice phishing email and see who clicks and who
reports it. People who click land on a page that says it was a test and lists
the warning signs they could have spotted. Results show click and report rates
per simulation and per person.

Dashboard → **Simulations** (owners and admins see results; only owners launch).

## Safeguards

These are enforced by the server, not only the dashboard:

| | |
|---|---|
| Who | Only an **owner** can launch, after entering an authenticator code (step-up), and must tick that they are authorised to test these people. Their email and the time are stored with the simulation and in the audit log. |
| Whom | Recipients must be on a **domain the company proved it controls** (or a subdomain of one): a TXT record, or a verified domain of the connected Microsoft 365 / Google Workspace tenant. The proof is checked again at every launch; a removed record removes the domain. |
| How | Emails go out only through the **company's own mail server** (Users → Email server) from its own address. The server-wide `SMTP_*` settings are never used, so a hosted PhishLens never sends phishing-like mail itself. |
| What | Five built-in templates with generic senders (IT Service Desk, Document Sharing, Parcel Delivery, Accounts Receivable, Account Security): no real brands or people, no attachments. |
| Landing page | No form, no password field (`form-action 'none'` CSP), `noindex`, no referrer. |
| Volume | 500 recipients per simulation, 5 simulations per 24 hours. |
| Marking | Every email has an `X-PhishLens-Simulation: <id>` header. |

## Proving a domain

Publish a TXT record, then press **Verify**:

```
_phishlens-sim.example.com.  TXT  "phishlens-sim=<value shown in the dashboard>"
```

The value is specific to your company. Alternatively connect the Microsoft 365
or Google Workspace check (Security); its verified domains count as proved.

## Making sure the emails arrive

The emails are sent by your own mail server, so SPF/DKIM pass for your domain.
Mail filters may still quarantine them because they look like phishing (that's
the point). To let them through:

- **Microsoft 365**: Defender portal → Email & collaboration → Policies →
  Advanced delivery → *Phishing simulation*: add your sending domain, your
  mail server's IP, and `APP_URL/s/*` as a simulation URL. Safe Links then
  leaves the link alone.
- **Google Workspace**: Admin console → Apps → Google Workspace → Gmail →
  Spam, phishing and malware → *Email allowlist* (your mail server's IP), or a
  routing rule that bypasses spam filtering for messages with the
  `X-PhishLens-Simulation` header.
- Other gateways: allow-list the header or your server's IP for the test.

## How clicks and reports are counted

- **Clicked**: the landing page's script reports the visit. Link scanners that
  only fetch the URL (Safe Links, gateways) don't run it, so they don't count.
- **Reported**: the person reported the email with the report-phish button
  (Outlook add-in, Gmail add-on) or it was uploaded to the report inbox. It is
  matched by the link in the email, counted as reported, and does **not**
  open an incident or takedown. The reporter sees "This was a phishing test
  from your IT team. Well done for reporting it!"

Deleting a simulation deletes its per-person results.

## Plans

On the hosted service simulations are in the Pro and MSP plans
(`simulations`). Self-hosted copies have everything.
