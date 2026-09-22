# Estate network security — what runs, where, and what it will not do

Built 2026-09-21. Everything here lives on **CT100** under `/opt/warden/`
and shares one SQLite store, `data/warden.db`.

## The finding that started this

CrowdSec appeared to be "hammered". It was not. The only local alert in seven
days was `crowdsecurity/http-probing` against `203.0.113.10` — **our own WAN
address**: an iPhone Immich client (`immich-ios/3.2.1`) requesting thumbnails
for eleven deleted assets in four seconds. CrowdSec's own console classifies
this as *"a security engine reported itself"*. warden agreed independently:
27 of 29 application-layer events in that week came from the same address.

The large numbers in `cscli metrics` (16,676 `http:scan`, 2,420 tor-exit,
1,015 firehol) are **CAPI community blocklists and third-party lists** —
addresses CrowdSec blocks pre-emptively because other people reported them.
They are not traffic that reached this estate. **Local alerts: 1.**

Two things follow, and they shape everything below:
1. The noise floor here is almost entirely self-inflicted, so *suppression
   matters more than detection*.
2. There was no real attack to defend against — the gaps are structural
   (no edge policy, no inside-the-network visibility), not an incident.

## Components

| what | where | schedule | mode |
|---|---|---|---|
| `warden.py` | log-side scoring (NPMplus, Authelia, cloudflared) | every 5 min | **detect-only** |
| `netscan.py` | LAN discovery + port drift | 15 min (discovery), daily 04:20 (ports) | **detect-only, no enforcement path** |
| `siemalert.py` | dispatch to `#network-admin-alerts` | every 5 min | sends |
| `cfsec.py` | Cloudflare audit + WAF rules | manual | dry-run by default |
| `edge-sentry/` | Cloudflare Worker | **not deployed** | detect-and-report |
| `warden-ui.py` | read-only dashboard, `:8792` behind Caddy | always | read-only |

## Design rules that are not negotiable

**Nothing blocks automatically.** warden proposes bans; `enforce: false`.
netscan has *no enforcement code at all* — acting against a LAN device (a
laptop, the printer, a door sensor) has a far worse blast radius than a late
alert. The Worker reports and never blocks, because a Worker that blocks can
lock you out at 3am with no UI to switch it off. Blocking belongs in WAF
rules, which are visible in a dashboard and revertible without a deploy.

**Suppressions are visible on the dashboard.** A filter you cannot see is
indistinguishable from a detector that has stopped working.

**A sweep that finds zero hosts is an error, not an empty network.** netscan
leaves all state untouched in that case; otherwise one broken sweep would mark
every known device as vanished.

## Tuning that was measured, not guessed

- **Learning window (`learn_hours: 48`).** An ARP sweep only sees devices that
  are awake. Two sweeps twelve minutes apart returned **48 then 46** devices,
  and six of the "new" ones were WiZ bulbs, a Nest and the TV that had simply
  been asleep. Without the window those are permanent false alarms. Do not set
  it to 0.
- **IP-change damping.** A Sonos alternates between `.114` and `.177`. A naive
  rule alerted on every sweep, forever. `net_host_ips` records every
  (MAC, IP) pairing ever seen, and `IP_CHANGE` fires only the first time a MAC
  appears at an address.
- **Multi-homing is decided before the host loop.** Deciding it inside the loop
  reported the same Sonos twice — once as a "move", once as a conflict.
- **`bc:24:11` is Proxmox VE.** nmap's shipped OUI table is dated April 2024
  and does not know it; 17 hosts were unidentified until `OUI_EXTRA` was added.
  Only verifiable entries go in that map — a guessed vendor name is worse than
  a blank one, because it makes an unknown device look identified.

## Two bugs found while building

1. **`net_overlaps_allow()` was missing from the live warden.** The fix was
   made in the published repo on 2026-09-10 and **never backported to
   `/opt/warden`**. Without it, a `/24` range ban could contain an allowlisted
   address — including our own WAN IP — and edge-ban us. Backported and
   verified: own `/24` refused, own `/16` refused, RFC1918 refused, Cloudflare
   refused, a genuinely hostile `/24` still bannable.
   *Lesson: a published repo and the running copy drift silently.*

2. **`union%20select` never matched.** The Worker scored `url.pathname +
   url.search`, which keeps percent-encoding, so an injection probe sailed
   past. Caught by the unit test, not by reading the code. **The WAF rule in
   `cfsec.py` had the identical flaw** and is now wrapped in `url_decode()` —
   it would have looked correct in the dashboard and blocked nothing.

Run the Worker tests with `cd /opt/warden/edge-sentry && node test.mjs`
(11 cases, including that `/.well-known/` must never alert — ACME and OIDC
discovery live there).

## ⛔ Blocked: Cloudflare needs a token

No token in this estate can touch zone settings or the WAF. All three are
narrow by design:

- Caddy (`/etc/caddy/caddy.env`) — DNS:Edit only
- NetBird (CT108) — Tunnel:Edit + DNS:Edit
- CrowdSec (CT106) — Firewall Access Rules only

`cfsec.py --audit` therefore reports settings and WAF as **UNREADABLE** rather
than as "nothing configured" — those are not the same thing.

To unblock, mint at **Cloudflare → My Profile → API Tokens → Custom**:
`Zone:Read` + `Zone Settings:Read` + `Zone WAF:Read` (add `Zone WAF:Edit` to
apply rules; `Workers Scripts:Edit` for the Worker). Then:

```sh
export CF_API_TOKEN=...
python3 /opt/warden/cfsec.py --audit
python3 /opt/warden/cfsec.py --apply-waf            # dry run
python3 /opt/warden/cfsec.py --apply-waf --commit   # writes
```

⚠️ Review the expressions before committing. A **host-wide** rate-limit rule
broke the NetBird dashboard outright on 2026-07-03: an SPA cold-loads far more
than 20 JS chunks, Cloudflare 429'd the overflow, a chunk returned as HTML, and
the browser threw `ChunkLoadError`. It read as an origin outage and was not.
Every proposed rule matches a specific hostile path or user agent — never a
whole hostname — and none touches `/.well-known/`, `/api/` or `/_next/`.

## Open items

- **4 public DNS records publish internal addressing.** several LAN-only
  hostnames → a private address, readable by anyone who runs `dig`.
  These are LAN-only services and NetBird already reaches them, so the public
  records are not required. Removing them is a decision, not an emergency.
- **VLAN 10 (IoT) is not covered.** An ARP sweep is layer 2 and CT100 has no
  VLAN10 interface. Adding the network to `netscan.yml` without adding that
  interface returns zero hosts *silently*, which is worse than not scanning.
- **Exposed hosts worth a look.** The daily port sweep found two LAN hosts
  running legacy file-sharing services (`rpcbind`, `netbios-ssn`, NFS, SMB)
  that nobody had reviewed. This is the class of finding the port sweep
  exists for: not an intrusion, just attack surface nobody chose.
- **A dynamic WAN lease will roll.** The allowlist of your own public
  addresses is the thing that stops warden edge-banning you; it has to be
  refreshed when the lease changes, in `self-ips` and in `warden.yml` both.

---

## ✅ 2026-09-21 (later) — Cloudflare edge is LIVE

The `WAF token` in **Infisical `/Cloudflare`** (note: the key name contains a
space) unblocked everything. `cfsec.py` now resolves it automatically.

**Token scopes, measured:**

| scope | state |
|---|---|
| Zone Settings:Read | ✅ |
| Zone WAF:Read + Edit | ✅ |
| Account Workers Scripts:Edit | ✅ *(was Read; user changed it)* |
| Zone Workers Routes:Edit | ✅ |
| DNS | ❌ 403 — the Caddy token covers DNS, and the audit uses both |
| Account listing | ❌ |

### ⚠️⚠️ The false negative that cost a wrong conclusion
`GET /accounts` returned **200 with an empty result**, and I read that as "no
Workers access". It is not. Listing accounts needs its own permission the
token does not have. **Test the endpoint you actually care about**, and get
the account id from `/zones/{id}` → `result.account.id` instead.

Likewise, to tell Workers **Read** from **Edit**, probe a write: a `DELETE` of
a non-existent script returns `403 No access` when read-only, and a
`404 / 10007` when writable. `GET` succeeding proves nothing.

### WAF: 3 custom rules live (were 0)
Verified against the live edge with `curl --resolve` (the LAN resolver has
split-horizon rewrites and would not have exercised the edge at all):

- blocked 403: `/.env`, `/.git/config`, `/wp-admin/`, `/phpmyadmin/`,
  `?id=1%20union%20select%201`, `benchmark(`, `sleep(`
- scanner UA `sqlmap/1.7-dev` → 403; normal UA → 200; `immich-ios/3.2.1` → 200
- **not** broken: OIDC discovery 200, Authelia 200, **NetBird SPA 200 and a
  10-parallel `/_next/` chunk burst all 404 (no 403, no 429)** — the exact
  2026-07-03 failure mode does not recur
- ⚠️ the `../` clause is effectively dead code: Cloudflare rejects traversal
  with **400 at the protocol layer before custom rules run**. Harmless, but do
  not count it as coverage.

### Worker `edge-sentry` DEPLOYED (6 routes)
Deployed with `edge-sentry/deploy.py` — **pure CF API, no wrangler/npm**.
Secrets go in as `secret_text` bindings, so the webhook URL is never in the
source. Discord webhook `edge-sentry` was created
via the bot once it had Manage Webhooks.

Verified end-to-end: three Worker-only probes produced three Discord alerts;
after restoring suppression the same three probes produced **none**.
All six hostnames served 200/302/303 in ~120ms throughout.

### ⚠️ WAF rules run BEFORE Workers — they do not overlap
`/.env` returned 403 and produced **no** Worker alert: the WAF blocked it
before the Worker ran. So `edge-sentry` only ever sees what the WAF lets
through. That is the right arrangement (no duplicate alerts), but it means
**the Worker's real coverage is the patterns the WAF does not block** —
`@fs/`, `/solr`, `/jenkins`, `/console`, `/etc/shadow`. Do not assume adding a
WAF rule leaves Worker visibility unchanged; it removes it.

### Operating notes
- `selftest.py off|on` toggles self-IP suppression for delivery testing.
  **Always run `on` afterwards** — left off, every Immich thumbnail 404 from
  the phone pages the channel, which is the original problem restored.
- ⚠️ Nested `ssh → pct exec → bash -c` heredocs break on quoting (hit again
  here). Stage the file and `pct push` it.
