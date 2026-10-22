# edge-sentry — deploy notes

✅ **DEPLOYED.** Verified 2026-10-22: the `edge-sentry` script is live and
routed on six hostnames (`obico`, `photos-1`, `auth-1`, `netbird`, `try`,
`listings`), and the `CF_API_TOKEN` (Cloudflare WAF token) can list both the
Workers scripts and routes on the account. (This supersedes the earlier
"NOT DEPLOYED" note — that predates the deploy.)

To ship an update (e.g. the security-header change in `worker.js`), just
re-run the deploy from `/opt/warden` — it re-uploads the script and leaves the
existing routes alone:
```sh
python3 edge-sentry/deploy.py   # reads CF_API_TOKEN + EDGE_WEBHOOK + cloudflare.edge_hosts from warden.yml
```

## What it does
Reports hostile requests to Discord from the Cloudflare edge, in real time,
with the true client IP, country and ASN. It never blocks — see the header
comment in `worker.js` for why blocking belongs in the WAF rules instead.

It also sets the security headers that warden's `webscan.py` reports as missing
— HSTS, X-Frame-Options, X-Content-Type-Options — on every response. This is a
purely additive change (it cannot block, redirect or drop a response), and it
never overrides a header the origin set deliberately. Values are overridable
per header via Worker secrets; set one to empty to skip it:
  - `HSTS` (default `max-age=31536000; includeSubDomains`)
  - `XFO`  (default `SAMEORIGIN`)
  - `XCTO` (default `nosniff`)

## Prerequisites
1. A Cloudflare API token with **Account → Workers Scripts:Edit** and
   **Zone → Workers Routes:Edit** on `example.com`.
2. A Discord **webhook URL** for your alert channel.
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
# should appear in your alert channel within a second or two
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
