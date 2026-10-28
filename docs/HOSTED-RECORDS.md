# Hosted DMARC, SPF, MTA-STS, TLS-RPT and BIMI

Customers delegate their records to PhishLens once; after that every policy
change is a click in the dashboard. PhishLens writes the real records into a DNS
zone you control on Cloudflare.

## One-time setup (you, the operator)

1. Pick a zone for hosted records, e.g. `hosted.phishlens.example`, and add it
   to Cloudflare (or use a subdomain of a zone you already have there).
2. Create a Cloudflare API token with **Zone → DNS → Edit** for that zone only.
3. Set in Render → Environment:
   - `HOSTED_ZONE=hosted.phishlens.example`
   - `HOSTED_CLOUDFLARE_TOKEN=<token>`
   - `HOSTED_CLOUDFLARE_ZONE_ID=<zone id from the zone's Overview page>`
   - `HOSTED_DMARC_RUA=dmarc@reports.hosted.phishlens.example` (the mailbox
     `scripts/fetch_dmarc_reports.py` reads; if it's inside `HOSTED_ZONE`,
     PhishLens also publishes the RFC 9990 external-reporting authorisation record for you)
   - Optional: `HOSTED_TLSRPT_RUA`, the mailbox hosted TLS-RPT records send
     reports to (defaults to `HOSTED_DMARC_RUA`; the report fetcher files both)
   - `MTA_STS_TARGET` = the hostname customers CNAME `mta-sts.<domain>` to
     (defaults to the app's own host)
   - Optional: `RENDER_API_KEY` + `RENDER_SERVICE_ID`, so PhishLens adds each
     `mta-sts.<customer domain>` as a Render custom domain and Render issues its
     TLS certificate. Without them, add each one by hand in Render → Settings →
     Custom Domains.
4. Run `scripts/rescan.py` on a schedule: it also re-flattens hosted SPF
   records when providers change their IP ranges.

## What customers publish

The dashboard shows the exact records per domain (and can publish them via
Cloudflare in one click). For example.com:

| Record | Customer publishes |
|---|---|
| DMARC | `_dmarc.example.com CNAME example.com.<tag>._dmarc.<HOSTED_ZONE>` |
| SPF | `example.com TXT "v=spf1 include:example.com.<tag>._spf.<HOSTED_ZONE> -all"` |
| MTA-STS | `_mta-sts.example.com CNAME example.com.<tag>._mta-sts.<HOSTED_ZONE>` and `mta-sts.example.com CNAME <MTA_STS_TARGET>` |
| TLS-RPT | `_smtp._tls.example.com CNAME example.com.<tag>._smtp._tls.<HOSTED_ZONE>` |
| BIMI | `default._bimi.example.com CNAME example.com.<tag>._bimi.<HOSTED_ZONE>` |

`<tag>` is unique per account, so two accounts can't overwrite each other's
records. MTA-STS policies are served only to the account the domain's
`_mta-sts` CNAME actually points at.

## Hosted TLS-RPT and BIMI

- **TLS-RPT**: the record is `v=TLSRPTv1; rua=...` with the team's report
  addresses (email or https), or the server's report mailbox.
- **BIMI**: the owner uploads an SVG logo. PhishLens checks it against SVG Tiny
  PS (the same check as the free logo checker on `/tools`) and only stores
  logos that pass. It serves the logo at `<APP_URL>/bimi/<id>/<version>.svg`
  (so `APP_URL` must be https) and publishes
  `v=BIMI1; l=<that URL>; a=<certificate URL, optional>`. A new logo gets a
  new URL, so inboxes fetch it again. Gmail and Apple Mail also need a VMC or
  CMC certificate from a certificate authority; PhishLens doesn't issue one.
