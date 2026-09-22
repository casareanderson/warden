# edge-sentry — deploy notes

⛔ **NOT DEPLOYED.** This is staged, not live. It could not be deployed or
tested from this session because no Cloudflare token in the estate has Workers
scope (the existing three are DNS:Edit, Tunnel+DNS:Edit, and Firewall Access
Rules only). Nothing below has been executed; treat it as reviewed code, not
verified code.

## What it does
Reports hostile requests to Discord from the Cloudflare edge, in real time,
with the true client IP, country and ASN. It never blocks — see the header
comment in `worker.js` for why blocking belongs in the WAF rules instead.

## Prerequisites
1. A Cloudflare API token with **Account → Workers Scripts:Edit** and
   **Zone → Workers Routes:Edit** on `example.com`.
2. A Discord **webhook URL** for `#network-admin-alerts`.
   Note this is a *webhook*, not the bot token used by `notify.py`: a Worker
   runs at the edge and cannot reach anything on the LAN, so it posts directly
   to Discord rather than through the estate's notifier.
   Create it in Discord: channel → Edit Channel → Integrations → Webhooks.

## Deploy
```sh
npm install -g wrangler
export CLOUDFLARE_API_TOKEN=...        # the Workers-scoped token
wrangler secret put ALERT_WEBHOOK      # paste the Discord webhook URL
wrangler secret put SELF_IPS           # e.g. 203.0.113.10
wrangler deploy
```

## Verify before trusting it
```sh
# should appear in #network-admin-alerts within a second or two
curl -s -o /dev/null "https://photos.example.com/.env"

# should NOT alert — /.well-known/ is excluded on purpose (ACME + OIDC)
curl -s -o /dev/null "https://auth.example.com/.well-known/openid-configuration"
```

## Free-plan limits
100,000 Worker requests/day. This zone serves six low-traffic hostnames, so
that is not a practical constraint — but the Worker is in the request path of
every one of them, which is exactly why it fails open on every error.

## Rolling it back
`wrangler delete` removes the script and its routes. Because the Worker only
observes, deleting it changes no security posture — the WAF rules are what
actually block.
