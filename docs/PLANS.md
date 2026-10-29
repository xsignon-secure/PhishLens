# Hosted plans (Free, Pro, MSP)

PhishLens is open source (MIT). A self-hosted copy leaves `PLANS_ENABLED`
off and every company gets every feature. The hosted service turns it on:

```
PLANS_ENABLED=true
```

Then each company has a plan, chosen at `/platform` when you create it and
changeable later from the company card. Payment is up to you (an invoice, then
set the plan). Nothing is deleted on a downgrade: data over the new limits, a
saved webhook, branding and so on are kept and come back after an upgrade.
Hosted DNS records keep being served on every plan, so a downgrade never
breaks a customer's mail.

| | Free | Pro | MSP |
|---|---|---|---|
| Monitored domains | 2 | 25 | Unlimited |
| Users | 2 | 10 | Unlimited |
| Automatic rescans (at most every) | 7 days | 24 hours | 1 hour |
| DMARC report domains | 1 | Unlimited | Unlimited |
| DMARC and TLS report history | 14 days | 1 year | 2 years |
| Audit log history | 7 days | 90 days | 1 year |
| Failure (RUF) reports, TLS reports | – | ✓ | ✓ |
| Weekly lookalike watch | – | ✓ | ✓ |
| Hosted records, one-click DNS fixes | – | ✓ | ✓ |
| Scheduled reports, shared report links | – | ✓ | ✓ |
| Webhooks and chat alerts, API keys | – | ✓ | ✓ |
| White-label (name, colour, logo, footer) | – | – | ✓ |
| SIEM and PSA / helpdesk tickets | – | – | ✓ |
| AI assistant connection (MCP) | – | – | ✓ |

The public scanner, the free tools, email alerts, extra alert addresses,
authenticator apps and every other security feature are in all plans.

How often rescans actually run is still set by `RESCAN_INTERVAL_HOURS`; a
plan can only make a company's rescans less frequent. For hourly MSP rescans
set it to 1.

The limits live in `app/plans.py`. Change the numbers there to change a plan.
