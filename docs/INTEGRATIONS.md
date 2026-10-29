# SIEM export, PSA tickets and test emails

## SIEM export

Dashboard → **SIEM and PSA** → SIEM export (owners). Every monitor alert is
sent as it happens, filtered by the alert types you tick.

**Syslog (RFC 5424).** Host, port and transport:

- `tls` (default, port 6514): RFC 5425, certificate verified against public CAs.
- `tcp` (port 514): RFC 6587 octet counting.
- `udp` (port 514): one datagram per alert.

Each alert is one message, facility local0, severity warning, app name
`phishlens`, MSGID the alert type (`score_drop`, `check_failed`,
`dns_changed`, `lookalike_registered`, `cert_expiring`), with structured data
you can extract fields from:

```
<132>1 2026-10-28T10:00:00Z phishlens.example.com phishlens - score_drop [phishlens@32473 domain="acme.com" client="Acme" kind="score_drop" score="50" grade="F"] acme.com: score fell from 90 to 50
```

**Splunk HTTP Event Collector.** The HEC URL (`https://splunk:8088` gets
`/services/collector/event` added), a HEC token and an optional index. Events
use sourcetype `phishlens:alert`.

Microsoft Sentinel, Elastic, QRadar, Graylog and others take syslog. For an
HTTP collector, the signed JSON **alert webhook** on the same page also works.

## PSA tickets

One ticket per domain each time it alerts (several alerts from one check go in
the same ticket), with the score and a link to the fixes. Pick the PSA and fill
in its fields:

| PSA | You need | Notes |
| --- | --- | --- |
| ConnectWise Manage | Site URL (e.g. `https://api-na.myconnectwise.net`), login company id, an API member's public and private key, a `clientId` from the ConnectWise developer portal, service board name, default company identifier | `POST /v4_6_release/apis/3.0/service/tickets` |
| HaloPSA | Halo URL, an API application's client id and secret (client credentials, scope `all`), tenant name for hosted Halo, optional ticket type id and default client id | `POST /api/tickets` |
| Autotask | Zone URL (e.g. `https://webservices5.autotask.net`), API user name, secret and integration code, default company id, optional queue id and priority (1 high, 2 medium, 3 low, 4 critical) | `POST /ATServicesRest/V1.0/Tickets`, status New |

**Client mapping.** If your monitors carry client labels, map each label to
the PSA's company id, one per line (`Acme = 12`). Unmapped domains go to the
default company.

**Send test** creates a real "PhishLens test ticket" so you can check the
board, company and permissions; close it afterwards.

These integrations follow each vendor's public API documentation but have not
been tried against live ConnectWise, HaloPSA or Autotask accounts yet. If a
test fails, the message on the page shows the PSA's answer; please open an
issue with it.

Secrets (private key, client secret, API secret, HEC token) are encrypted with
a key derived from `SECRET_KEY` and never sent back to the browser. Rotating
`SECRET_KEY` makes them unreadable: enter them again. Every destination must
be a public host, and HTTP APIs must use https.

The older route still works too: an extra alert email address on the dashboard
can be the PSA's email-to-ticket inbox.

## Send a test email

Signed-in users get a one-off address on `/tools/headers`, send a message to
it from any service they use (their mailbox, a newsletter tool, a helpdesk),
and see what the receiving server recorded: SPF, DKIM and DMARC results,
whether DKIM aligns with the From domain, Reply-To tricks and the delivery
path. Only that analysis is stored, never the message, and a team's tests
older than a week are deleted when it starts a new one.

Setup:

1. Use the mailbox that `scripts/fetch_dmarc_reports.py` already reads
   (IMAP, Microsoft 365 or Gmail; see that script's header).
2. Set `MAILTEST_ADDRESS` to an address that lands in it, for example
   `check@reports.yourdomain.com`. Each test uses `check+<token>@...`, so the
   mailbox must accept plus addressing (Gmail, Microsoft 365 and most hosts do).
3. Run the fetch on a schedule (`REPORT_FETCH_MINUTES=5` is good for tests) or
   let users press **Check now**, which reads the mailbox right away.

The verdict comes from the receiving server's own `Authentication-Results`
header, so the mailbox should be at a provider that checks SPF, DKIM and
DMARC (all the big ones do).
