# Known issues

The honest list. warden runs in **detect-only** by default, where none of the
enforcement caveats below apply. Read this before you flip `enforce: true`.

## Enforcement is less proven than detection

- **The Cloudflare enforcement path is not battle-tested.** warden proposes
  bans continuously and those proposals are correct; but `cf_ban()` posts to the
  account **IP Access Rules** API, and Cloudflare has been moving customers off
  the legacy firewall APIs. Before you trust `enforce: true`, confirm that
  endpoint still accepts writes on your account, or point `cf_ban()` at whatever
  Cloudflare's current equivalent is. Detect-only does not call it.
- **A ban never expires in practice.** `ban_hours` and an `expires` timestamp
  are written to the database, but nothing removes the Cloudflare rule when the
  window lapses — there is no unban path yet. Edge rules accumulate until you
  clear them by hand. Fine while proposing; a real gap once enforcing.

## Detection edges

- **Bursts are capped.** The tunnel collector reads `docker logs ... | tail -400`
  per sweep; more than ~400 malicious lines inside one 5-minute window lose the
  overflow. It undercounts (safe direction), never over-bans.
- **A broken log connection looks like a quiet one.** If the SSH to the log host
  fails, the collector returns empty — indistinguishable, inside warden, from
  "nothing new". Watch the dashboard's per-source line counts; a healthy source
  that suddenly reads 0 is the signal.
- **cloudflared logs the edge IP, not the client**, so attacks seen only in the
  tunnel log are recorded but unattributed — they score the target, not a
  bannable address. Attribution has to come from the access log.

## Coupling

The three collectors are specific to one estate's log layout (container names,
paths, an SSH+docker hop). Treat them as worked examples and adapt them; the
scoring, timestamp handling, dedup, /24 roll-up and edge-ban logic are general.
