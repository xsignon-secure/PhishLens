# One-click publishing with Domain Connect

[Domain Connect](https://www.domainconnect.org) is an open standard that lets
a user publish DNS records without an API token: they click "Publish with
GoDaddy" (or IONOS, Cloudflare, WordPress.com and other hosts that support
it), sign in at their DNS host, approve the change, and the host adds the
records. PhishLens uses it when a team hasn't connected a DNS API token.

It is off until you set it up, because every DNS host only accepts templates
that are registered in the public templates repository.

## 1. Pick your IDs

- `DOMAIN_CONNECT_PROVIDER_ID`: a domain you own that names you as the
  template provider, e.g. `phishlens.example.org`.
- `DOMAIN_CONNECT_KEY_DOMAIN`: where you publish the signing public key, e.g.
  `dc.phishlens.example.org`.
- `DOMAIN_CONNECT_PROVIDER_NAME`: shown to users at the DNS host (default
  "PhishLens").

## 2. Make a signing key

```bash
python scripts/domain_connect.py keygen
```

It prints the private key and the TXT records to publish at
`_dck1.<DOMAIN_CONNECT_KEY_DOMAIN>`. Publish the TXT records, and set the
private key as `DOMAIN_CONNECT_PRIVATE_KEY` (a secret; the one-line form with
`\n` escapes works in Render's environment settings).

## 3. Register the templates

```bash
DOMAIN_CONNECT_PROVIDER_ID=... DOMAIN_CONNECT_KEY_DOMAIN=... APP_URL=https://your.app \
  python scripts/domain_connect.py templates templates-out/
```

This writes one template per record kind (DMARC, SPF, MTA-STS, TLS-RPT,
BIMI, and the hosted-record CNAMEs). Open a pull request adding them to
<https://github.com/Domain-Connect/Templates>. Once it is merged, each DNS
host picks the templates up on its own schedule; PhishLens checks per domain
whether the host has them before offering the button.

Templates are signed (`syncPubKeyDomain`) because their values are variables,
and they only redirect back to your `APP_URL` host (`syncRedirectDomain`).

## 4. Turn it on

Set the three settings above and restart. Owners without a connected DNS
token then see "Apply in <host>" on fix cards, hosted records and the setup
wizard whenever the domain's DNS host supports Domain Connect. PhishLens
only builds the link; nothing changes until the user approves it at their
DNS host, and the same record rules as token publishing apply (only SPF,
DMARC, MTA-STS, TLS-RPT and BIMI records, and CNAMEs to PhishLens hosted
records, for domains the team scans or monitors).
