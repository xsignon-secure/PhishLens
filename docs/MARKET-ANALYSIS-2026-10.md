# PhishLens vs. the market (October 2026)

Who PhishLens competes with, where it was behind, and what this release changes.
Pricing is as published by the vendors or by review sites in October 2026; check
before quoting it to a customer.

## The competitors

| Product | Price (entry) | What it's known for |
|---|---|---|
| **EasyDMARC** | Free (1 domain); Plus €35.99/mo (2 domains); Premium €71.99/mo (4 domains) | DMARC report dashboards, hosted SPF/DMARC/MTA-STS/BIMI, free lookup tools, MSP console |
| **MXToolbox** | Free lookups; Basic $19/mo (1 domain); Business $49/mo (10 domains) | 30+ test domain health check, 100+ blocklists, Delivery Center monitoring, email/SMS alerts |
| **PowerDMARC** | Unpublished (from ~$8/mo for MSPs) | All protocols in one dashboard, hosted SPF macros, MTA-STS hosting, real-time alerts, multi-tenant |
| **dmarcian** | Limited free tier; paid unpublished | Clear DMARC report visualisation, SPF surveyor |
| **Valimail (DigiCert)** | Enterprise only | Automated SPF/DKIM sender management, SSO |
| **Red Sift OnDMARC** | Enterprise / MSP flat rate | Dynamic SPF, MTA-STS hosting, API-first, lookalike monitoring (Brand Trust) |
| **DMARC Report** | Free (1 domain); from $25/mo | Report dashboards, hosted DMARC/MTA-STS/BIMI, REST API, SSO/RBAC |
| **Postmark DMARC Digests** | Free weekly digest; $14/mo per domain | Simple weekly email summary of DMARC reports |

## Feature comparison

✓ = has it · ◐ = partial · ✗ = missing · ? = not confirmed from public sources

| Capability | EasyDMARC | MXToolbox | PowerDMARC | Red Sift | PhishLens before | PhishLens now |
|---|---|---|---|---|---|---|
| One-pass scan of SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT/DNSSEC/CAA/TLS/headers | ◐ separate tools | ✓ | ✓ | ✓ | ✓ | ✓ |
| Exact fix record per issue + prioritised plan | ◐ generators | ✗ | ◐ | ◐ | ✓ | ✓ |
| DKIM selector auto-detection + key strength | ◐ | ✗ | ◐ | ◐ | ✓ | ✓ |
| **DMARC aggregate (RUA) report analysis** | ✓ | ◐ paid | ✓ | ✓ | ✗ | ✓ upload, API, mailbox ingest |
| **Sender identification + "safe to enforce" guidance** | ✓ | ✗ | ✓ | ✓ | ✗ | ✓ |
| **Lookalike / typosquat domain monitoring** | ? | ✗ | ? | ✓ (Brand Trust, separate product) | ✗ | ✓ with weekly new-registration alerts |
| **Email header analyzer** | ✓ free tool | ✓ free tool | ✓ | ? | ✗ | ✓ free, public |
| Blocklist checks | ✓ | ✓ 100+ | ✓ | ◐ | ◐ 2 lists | ◐ 10 lists incl. 3 domain lists |
| Monitoring + drift alerts | ✓ | ✓ paid | ✓ | ✓ | ✓ | ✓ |
| **Slack / Teams alerts** | ✓ Premium | ✗ | ✓ | ✓ | ✗ (raw JSON only) | ✓ Slack, Teams, Discord |
| Signed SIEM webhooks | ✓ Enterprise | ✗ | ✓ | ✓ | ✓ | ✓ |
| REST API + keys | ✓ Premium | ✓ Business | ✓ | ✓ | ✓ | ✓ |
| PDF reports, shareable links, score history | ◐ | ✗ | ✓ | ✓ | ✓ | ✓ |
| MFA, audit log, data export | ✓ | ◐ | ✓ | ✓ | ✓ | ✓ |
| Hosted SPF / DMARC / MTA-STS (CNAME delegation) | ✓ | ✗ | ✓ | ✓ | ✗ | ✓ incl. SPF flattening |
| Forensic (RUF) reports | ✓ | ✗ | ✓ | ✓ | ✗ | ✓ headers only, no bodies |
| One-click DNS-provider integrations | ✓ | ✗ | ◐ | ◐ | ✗ | ◐ Cloudflare |
| SSO | ✓ Premium | ✗ | ✓ | ✓ | ✗ | ✓ OpenID Connect (no SAML) |
| MSP white-label + PSA integrations | ✓ | ✗ | ✓ | ✓ | ◐ multi-tenant | ◐ branding, client tags, PSA email-to-ticket |
| Paid plans wired to billing | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ Stripe |

## What this release closes

1. **DMARC report analysis.** The core of every paid DMARC product, and the
   biggest gap. Upload .xml/.gz/.zip reports in the dashboard, POST them to
   `/api/dmarc/reports` with an API key, or run `scripts/fetch_dmarc_reports.py`
   against a shared report mailbox. The summary groups traffic by sending
   service (Google Workspace, Microsoft 365, SendGrid, ...), shows pass rates,
   tells you how to fix each failing sender, and says when it's safe to move to
   `p=quarantine` / `p=reject` (≥98% passing over at least 14 days).
2. **Lookalike domains.** PhishLens is pitched on phishing, yet it couldn't see
   the look-alike domains phishers register. It now generates several hundred
   typo, homoglyph, keyword and TLD variants, checks which exist, and ranks the
   ones with mail servers as high risk. Monitored domains are rechecked weekly by
   `scripts/rescan.py` and alert on new registrations.
3. **Email header analyzer** at `/tools/headers`: free, no signup, nothing
   stored. Reads SPF/DKIM/DMARC verdicts and flags Reply-To redirection, fake
   display-name addresses and punycode senders. It's the top-of-funnel tool
   EasyDMARC and MXToolbox use to pull in visitors, and it fits XSignOn's
   phishing story.
4. **Slack, Teams and Discord alerts.** Pasting a chat webhook URL now posts a
   readable message (an Adaptive Card for Teams) instead of raw JSON.
5. **Blocklists.** Up from 2 to 6: Spamhaus ZEN, SpamCop, PSBL and Mailspike for
   mail server IPs, plus Spamhaus DBL and SURBL, which list the domain itself
   when it shows up in spam or phishing.

## Second round (filled the rest)

6. **Billing**: Stripe Checkout and Customer Portal; Free (3 domains) and Pro
   (100 domains plus the features below). Only Stripe's signed webhook changes
   a plan. See `docs/BILLING.md`.
7. **Hosted DMARC / SPF / MTA-STS**: one-time CNAME/include delegation, then
   policy changes in the dashboard. SPF is flattened to IPs (no more 10-lookup
   failures) and re-flattened on each scheduled rescan. MTA-STS policies are
   served by PhishLens. See `docs/HOSTED-RECORDS.md`.
8. **One-click fixes** through the customer's Cloudflare account, limited to
   email-auth records on their own domains.
9. **Forensic (RUF) reports** from the report mailbox or .eml upload.
10. **SSO** with OpenID Connect, just-in-time member provisioning, optional
    enforcement. See `docs/SSO.md`.
11. **White-label** reports, PDFs and alert emails; client tags; extra alert
    recipients for PSA email-to-ticket inboxes.
12. **Blocklists**: 10 (adds Barracuda, DroneBL, Manitu, URIBL).

## Still behind

- **SAML** (OIDC covers Okta, Entra ID, Google and most IdPs).
- **Native PSA APIs** (ConnectWise/Autotask/HaloPSA ticket APIs); email-to-ticket
  covers the common case.
- **DNS providers beyond Cloudflare** (Route 53, GoDaddy) for one-click fixes.
- **100+ blocklists**: most of MXToolbox's long tail is low-value or paid.

## Positioning

PhishLens now matches the mid-market DMARC tools on the essentials (scan, fix,
report analysis, monitoring, alerts, API) and beats them on three things:
exact fix records for every finding (now publishable in one click), lookalike-domain
alerts built in rather than sold as a separate brand-protection product, and a
free header checker plus domain scanner with no signup. Against EasyDMARC Plus (€35.99/mo for 2
domains), pricing PhishLens per domain below that, with lookalike monitoring
included, is a clear story.

Sources: [dmarcreport.com comparison](https://dmarcreport.com/blog/best-dmarc-reporting-tools-2026/),
[EasyDMARC review (dupple.com)](https://dupple.com/reviews/easydmarc),
[MXToolbox overview (spotsaas.com)](https://www.spotsaas.com/blog/mxtoolbox),
[dnstwist](https://github.com/elceef/dnstwist/blob/352bbcd585d5a43751fe5d3c14a263835a6b6f19/docs/README.md).
