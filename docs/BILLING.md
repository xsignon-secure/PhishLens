# Billing (Stripe)

Without Stripe keys PhishLens runs with every feature unlocked (self-hosted
mode). With them, tenants start on **Free** (3 monitored domains) and upgrade to
**Pro** (100 domains, hosted records, one-click Cloudflare fixes, SSO,
white-label reports, extra alert recipients).

## Set up

1. In Stripe, create a Product "PhishLens Pro" with a recurring Price. Copy the
   price id (`price_...`).
2. Developers → API keys: copy the secret key (`sk_live_...`; use `sk_test_...`
   first).
3. Developers → Webhooks → Add endpoint:
   `https://<your app>/api/billing/webhook`, events
   `checkout.session.completed`, `customer.subscription.updated`,
   `customer.subscription.deleted`. Copy the signing secret (`whsec_...`).
4. Settings → Billing → Customer portal: turn it on (lets customers update cards
   and cancel).
5. Set `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID` and `STRIPE_WEBHOOK_SECRET` in
   Render → Environment, then redeploy.

Only the signed webhook changes a tenant's plan: the redirect back from
Checkout doesn't, so it can't be faked. Test with Stripe's test card
`4242 4242 4242 4242`.
