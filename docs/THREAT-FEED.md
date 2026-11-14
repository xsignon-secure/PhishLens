# Threat feed (STIX 2.1 / TAXII 2.1)

PhishLens publishes what it finds for your company as threat indicators your
SIEM, SOAR or firewall can block or alert on.

## What's in it

| Source | Indicator | Confidence | Type |
|---|---|---|---|
| Registered lookalike of a monitored domain | domain | 40; 60 if the site resembles yours, 70 if it asks for a password, 85 if it copies your site; +10 with a TLS certificate | anomalous, malicious when it copies your site |
| Link in a reported email that the link checker rates *dangerous* or *likely phishing* | URL and domain | 65, 80 when an admin confirmed the report, 90 when *dangerous* | malicious when dangerous or confirmed |
| Sender of a report an admin **confirmed** as phishing | email address | 75 | malicious |
| Takedown request (not closed) | domain and URL | 90 | malicious |

Never included: your monitored domains and their subdomains, links the
checker found clean, reports marked *false positive*, sender addresses of
unconfirmed reports (they are often spoofed real addresses), and reports older
than 90 days.

Each indicator has a stable STIX id. When its source goes away (the lookalike
lapses, the report is marked a false positive, the takedown is closed) it stays
in the feed with `"revoked": true`, so SIEMs that pulled it remove it.

## Authentication

Create an API key in **Dashboard → Integrations → API keys**. The feed accepts
it as:

- HTTP Basic: any username, the key as the password (Sentinel, firewalls);
- `X-API-Key: plk_…` or `Authorization: Bearer plk_…`.

Each key only sees its own company's indicators. On the hosted service the feed
is part of the MSP plan (`siem_psa`).

## TAXII 2.1

| | |
|---|---|
| Discovery | `https://YOUR-HOST/taxii2/` |
| API root | `https://YOUR-HOST/taxii2/api/` |
| Collection ID | `0b5e2a3c-9f7d-4c6b-8e1a-7d3f4c2b1a90` |

Supported: collections, `objects` (with `added_after`, `limit`, `next`,
`match[id]`, `match[type]`), single objects and `manifest`. The collection is
read-only. Pages hold up to 1000 objects.

### Microsoft Sentinel

1. **Content hub** → install the **Threat Intelligence** solution.
2. **Data connectors** → **Threat Intelligence - TAXII** → **Open connector page**.
3. Friendly name `PhishLens`, API root URL and Collection ID from above,
   username `phishlens`, password = the API key. Import: *All available*.
   Polling: *Once an hour*.
4. Indicators appear under **Threat intelligence**; the built-in *TI map Domain
   entity to …* and *TI map URL entity to …* analytics rules then match them
   against your sign-in, DNS, proxy and email logs.

### Splunk Enterprise Security

Configure → Data Enrichment → Threat Intelligence Management → Sources → New
→ TAXII. URL is the objects endpoint
(`https://YOUR-HOST/taxii2/api/collections/0b5e2a3c-9f7d-4c6b-8e1a-7d3f4c2b1a90/objects/`),
with the API key as the password. Or download the STIX bundle on a schedule.

### Elastic Security

Use the **Threat Intelligence - TAXII** (`ti_custom` / Filebeat
`threatintel` TAXII) input with the same URL and Basic credentials.

### OpenCTI / MISP

OpenCTI: *Data → Ingestion → TAXII feeds*. MISP: the `misp-taxii` connector,
or import `stix.json`.

## Downloads

| URL | |
|---|---|
| `/api/threat-feed/stix.json` | STIX 2.1 bundle of live indicators |
| `/api/threat-feed/indicators.csv` | CSV: type, value, confidence, malicious, sources, dates, description |
| `/api/threat-feed/domains.txt` | One domain per line (firewall external block list / EDL, DNS filter) |
| `/api/threat-feed/urls.txt` | One URL per line |
| `/api/threat-feed/emails.txt` | One sender address per line (mail gateway block list) |

All take `?min_confidence=0-100`; for automatic blocking `?min_confidence=70`
is a sensible start. Example for a Palo Alto external dynamic list: type
*Domain List*, source `https://YOUR-HOST/api/threat-feed/domains.txt?min_confidence=70`,
client authentication with any username and the API key as the password.

The feed is rebuilt each time it is read, so it is always current. Requests
are limited to 240 per hour per company.
