# Hosted DMARC, SPF and MTA-STS

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

`<tag>` is unique per account, so two accounts can't overwrite each other's
records. MTA-STS policies are served only to the account the domain's
`_mta-sts` CNAME actually points at.
