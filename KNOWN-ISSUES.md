# Known issues

The honest list. warden runs in **detect-only** by default, where none of the
enforcement caveats below apply. Read this before you flip `enforce: true`.

## Enforcement is less proven than detection

- **The Cloudflare enforcement path is still not battle-tested.** warden
  proposes bans continuously and those proposals are correct; `cf_ban()` now
  appends to the zone's `warden: blocklist` **WAF custom rule** — Cloudflare's
  current equivalent of the retired firewall APIs, the same rule `edgeban.py`
  maintains — instead of the legacy account IP Access Rules API. That request
  shape is unit-tested against a fake API, but no test here can prove the
  endpoint accepts writes on *your* account, so before you trust `enforce:
  true`, run `edgeban.py sync` once and confirm the rule lands in Cloudflare.
  Detect-only does not call `cf_ban()`.
- **An allowlist that is stale is worse than no allowlist.** `net_overlaps_allow()`
  is what stops a `/24` roll-up from containing your own WAN address and banning
  you at the edge, and the log-side roll-up now reads `self-ips.txt` too — the
  same "addresses that are us" set edgeban already honours — so a `/24` holding
  an address you listed there is refused, not just one in `warden.yml allow`. It
  is tested (own `/24`, own `/16`, RFC1918 and Cloudflare's ranges are all
  refused; a genuinely hostile `/24` is still bannable). What remains: nothing
  discovers your WAN address for you, so on a dynamic lease you must keep
  `self-ips.txt` current.
- **Enforced bans now expire, but the unban path is as unproven as the ban
  path.** `cf_unban()` removes a lapsed address from the `warden: blocklist`
  rule once `expires` passes, so edge rules no longer pile up until cleared by
  hand. It is unit-tested against the same fake API as `cf_ban()`, not against
  a live account; a failed unban leaves the ban `active` and retries next
  sweep. Confirm with `edgeban.py sync` once, as for banning.

## Detection edges

- **A broken log connection is flagged, not silent.** If the SSH to a log host
  (or a local `docker logs` read) fails, the collector records a `BLIND: …` note
  on that source and leaves its watermark in place, so the Health tab shows it as
  `blind` and the unread lines are not lost — no longer mistaken for "nothing
  new". A source that is simply not configured is still skipped with no note.
- **cloudflared logs the edge IP, not the client**, so attacks seen only in the <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  tunnel log are recorded but unattributed — they score the target, not a
  bannable address. Attribution has to come from the access log.

## Coupling

The collectors are configurable (`sources:` in warden.yml: SSH target, container,
log path) but the **parsers** assume six formats: NGINX/NPMplus access logs,
Authelia, cloudflared, Caddy (JSON), Traefik (CLF) and Authentik. Other proxies
or SSO portals need a parser; the scoring, timestamp handling, dedup, /24
roll-up and edge-ban logic are general.

## v2: API, MCP and approvals

- **Serve it over TLS.** `/api/v1` and `/mcp` use bearer tokens. Over plain HTTP <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  on an untrusted network a token can be sniffed — put warden behind a TLS proxy
  before agents on other machines connect to it.
- **Your proxy must not put a login page in front of `/mcp` or `/api/v1`.** An MCP <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  client cannot follow a redirect; it receives HTML, reports a parse error, and the
  real cause is invisible from the agent's side.
- **A dashboard approval is the owner's approval.** Anyone who can reach the console <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  can approve a patch plan. That is why the console binds to localhost and expects
  auth in front of it — don't expose it without some.
- **Large estates make big MCP answers.** Tool results are capped at 200 KB and
  say so when truncated; ask narrower questions (a target, an IP, fewer hours).
- **Vulnerability matching needs OSV.dev to see new advisories.** When it is unreachable the scan no longer
  errors per target: it matches against the advisories already fetched into the local cache and marks the
  target `stale` (Alpine also falls back to its cached secdb). What a `stale` result cannot show is an
  advisory never fetched — a new CVE, or a package first seen that day — so it can under-report until OSV
  is reachable again.
- **Package types not read inside images:** Java jars, Ruby gems, PHP composer, .NET, and Go binaries older than
  Go 1.18 (counted in the target's note). Rust binaries are read only when built with `cargo auditable`.
- **Renamed forks are invisible.** A fork published under a new name (e.g. `unclecode-litellm`, a litellm 1.81 fork)
  matches no advisories for the original project.

## netscan

- **It is layer 2, so it only sees networks you have an interface on.** Adding a <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  network to `netscan.yml` without an interface on it returns zero hosts
  **silently** — which reads identically to "that network is clean". Do not list
  a VLAN you cannot ARP.
- **`learn_hours` is not optional.** An ARP sweep only sees devices that are <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  awake. Two sweeps twelve minutes apart here returned 48 then 46 devices, and
  six of the "new" ones were bulbs and a TV that had been asleep. Setting it to
  0 turns those into permanent false alarms.
- **OUI tables go stale.** nmap's shipped vendor table did not know a prefix
  that accounted for 17 hosts. Only put verifiable entries in `OUI_EXTRA`: a
  guessed vendor name is worse than a blank one, because it makes an unknown
  device look identified.

## edge-sentry

- **Not deployed by this repo.** `deploy.py` needs a Cloudflare token with <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  Workers Scripts:Edit *and* Zone Workers Routes:Edit, and `DEPLOY.md` spells
  out how to prove you have Edit rather than Read.
- **It reports, it never blocks.** That is deliberate and should stay that way; <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  put blocking in WAF rules where a dashboard can revert it.
- **Cloudflare rejects path traversal at the protocol layer**, with a 400, <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
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

## Heartbeat and sign-ins (v3)

- **Containers inside Docker are not heartbeat-checked one by one.** A stopped container on a box that is up still
  looks fine. On the author's estate a host OS update left three `unless-stopped` containers (the reverse proxy among
  them) stopped after the reboot, because the update had run `docker stop` on them, and nothing in warden flagged it.
  Watching declared containers is the next step.
- **Only sign-ins that sshd or `last` record are seen.** `pct exec`, `lxc-attach` and the Proxmox web console don't
  write a sign-in line, so a session started that way never shows up.
- **A shared key hides its users.** "Self" is any key that lives on the warden box. If another job on that box signs <!-- steward: skip (advice, design or upstream; not for the coding agent) -->
  in with the same key, it is left out too. Give jobs their own keys and name them in `logins.known_keys`.
- **Container sign-ins and heartbeats need Proxmox** (`pct`, `pvesh`). Containers on other hypervisors are not seen.
