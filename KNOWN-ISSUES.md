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
- **An allowlist that is stale is worse than no allowlist.** `net_overlaps_allow()`
  is what stops a `/24` roll-up from containing your own WAN address and banning
  you at the edge. It is tested (own `/24`, own `/16`, RFC1918 and Cloudflare's
  ranges are all refused; a genuinely hostile `/24` is still bannable) — but it
  can only refuse addresses you told it about. On a dynamic WAN lease, refresh it.
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

The collectors are configurable (`sources:` in warden.yml: SSH target, container,
log path) but the **parsers** assume three formats: NGINX/NPMplus access logs,
Authelia, and cloudflared. Other proxies or SSO portals need a parser; the
scoring, timestamp handling, dedup, /24 roll-up and edge-ban logic are general.

## v2: API, MCP and approvals

- **Serve it over TLS.** `/api/v1` and `/mcp` use bearer tokens. Over plain HTTP
  on an untrusted network a token can be sniffed — put warden behind a TLS proxy
  before agents on other machines connect to it.
- **Your proxy must not put a login page in front of `/mcp` or `/api/v1`.** An MCP
  client cannot follow a redirect; it receives HTML, reports a parse error, and the
  real cause is invisible from the agent's side.
- **A dashboard approval is the owner's approval.** Anyone who can reach the console
  can approve a patch plan. That is why the console binds to localhost and expects
  auth in front of it — don't expose it without some.
- **Large estates make big MCP answers.** Tool results are capped at 200 KB and
  say so when truncated; ask narrower questions (a target, an IP, fewer hours).
- **Run the trivy server with its token in a file or environment file,** not on its
  command line — `--token` on the command line is readable by every local user via `ps`.

## netscan

- **It is layer 2, so it only sees networks you have an interface on.** Adding a
  network to `netscan.yml` without an interface on it returns zero hosts
  **silently** — which reads identically to "that network is clean". Do not list
  a VLAN you cannot ARP.
- **`learn_hours` is not optional.** An ARP sweep only sees devices that are
  awake. Two sweeps twelve minutes apart here returned 48 then 46 devices, and
  six of the "new" ones were bulbs and a TV that had been asleep. Setting it to
  0 turns those into permanent false alarms.
- **OUI tables go stale.** nmap's shipped vendor table did not know a prefix
  that accounted for 17 hosts. Only put verifiable entries in `OUI_EXTRA`: a
  guessed vendor name is worse than a blank one, because it makes an unknown
  device look identified.

## edge-sentry

- **Not deployed by this repo.** `deploy.py` needs a Cloudflare token with
  Workers Scripts:Edit *and* Zone Workers Routes:Edit, and `DEPLOY.md` spells
  out how to prove you have Edit rather than Read.
- **It reports, it never blocks.** That is deliberate and should stay that way;
  put blocking in WAF rules where a dashboard can revert it.
- **Cloudflare rejects path traversal at the protocol layer**, with a 400,
  before custom rules run. A `../` clause in a WAF rule is dead code. Harmless,
  but do not count it as coverage.

## Threat-list blocking (planned) — rules decided before it is built

A reader pointed out (2026-10-10) that feeds which mark whole cloud ASNs as "proxy" cause collateral damage when turned
into bans: CI and monitoring egress share those ranges. warden does not ban from threat lists today (feeds only alert
about your own devices; edge bans come from behaviour against your own site, approved by you). When list-based blocking
is added it will follow these rules:

- **Never on one source.** A datacenter / proxy / hosting mark needs at least two independent, specialised sources.
  A single-source datacenter mark is treated as noise.
- **Challenge, not block,** for datacenter ranges, so legitimate automated traffic can still pass.
- **A service-egress allowlist** (published ranges such as GitHub's meta API for Actions and webhooks, your uptime
  checkers, ACME validation) is never banned. This also applies to today's edge-ban proposals.
- **No range wider than a /24,** never a whole ASN or cloud provider.
