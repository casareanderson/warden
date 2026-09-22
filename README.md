# warden

A small, dependency-free intrusion detector for a homelab behind Cloudflare —
one Python file, the standard library, and SQLite. It reads the logs your WAF
can't see, scores hostile behaviour, and proposes bans **at the Cloudflare edge**,
because that is the only place the attacker's real address is both visible and
blockable.

It ships **detect-only**. It will not touch anything until you tell it to.

## The one idea worth stealing

If your services sit behind a Cloudflare tunnel, a local `iptables` ban is
useless. At layer 3 every packet's source is Cloudflare's edge — the attacker's
real IP exists **only** in the HTTP layer (`CF-Connecting-IP`). So:

- a local ban keyed on the attacker never matches a packet, and
- banning what *does* arrive at L3 bans Cloudflare and takes your whole estate
  offline.

warden reads the attacker's real IP out of the access logs and enforces with
**Cloudflare IP Access Rules**, before traffic ever enters the tunnel. That's
the whole reason it exists.

## What it does

- Tails three log sources on a timer (every 5 min): an nginx/NPM access log, an
  Authelia auth log, and the `cloudflared` tunnel log — the last being the only
  place direct-to-origin hostnames show up.
- Scores requests against a small rule set: path traversal, `/etc/passwd`,
  `.env`/`.git` probes, SQLi signatures, scanner user-agents, WordPress/phpMyAdmin
  sweeps, and a point for bare 4xx noise.
- Proposes a ban when one IP crosses a score threshold inside a window, and
  rolls activity up to a **/24** to catch an attacker spread thin across a
  subnet below the per-IP threshold.
- Serves a read-only dashboard (no "ban" button by design).

## Three things it gets right (learned the hard way)

1. **An event's time is the time in the log line, not the time you read it.**
   The first run ingests a whole backlog at once; timestamp it with "now" and
   weeks of history land inside your "last 60 minutes" ban window — and with
   enforcement on, you ban someone for something they did in July.
2. **A fixed `--since 10m` under a 5-minute timer double-counts everything.**
   Use a real watermark, plus a content hash as belt-and-braces against
   restarts and rotation.
3. **A per-IP threshold is blind to subnet-spread.** Seven addresses in one /24,
   each just under the line, is an attack the per-IP rule never sees.

## What's in the repo

`warden.py` is the original log-side detector. Three pieces have since been
built around it, and they share one SQLite store:

| file | what it does | mode |
|---|---|---|
| `warden.py` | scores hostile behaviour in nginx / Authelia / `cloudflared` logs | detect-only |
| `netscan.py` | ARP + TCP discovery of the LAN, new-device and port-drift alerts | **detect-only, no enforcement code at all** |
| `siemalert.py` | pushes new findings to a chat webhook | sends |
| `cfsec.py` | audits the Cloudflare zone and proposes custom WAF rules | **dry-run by default** |
| `edge-sentry/` | a Cloudflare Worker that reports hostile requests at the edge | detect-and-report |

[NETSEC.md](NETSEC.md) is the field notes: what each one found, what was
measured rather than guessed, and the bugs that turned up while building them.

## Design rules that are not negotiable

**Nothing blocks automatically.** warden proposes bans; `enforce: false`.
`netscan` has no enforcement path at all, because acting against a LAN device
— a laptop, a printer, a door sensor — has a far worse blast radius than a
late alert. The Worker reports and never blocks, because a Worker that blocks
can lock you out at 3am with no UI to switch it off. Blocking belongs in WAF
rules: visible in a dashboard, revertible without a deploy.

**A sweep that finds zero hosts is an error, not an empty network.** Otherwise
one broken sweep marks every known device as vanished.

**Suppressions are visible on the dashboard.** A filter you cannot see is
indistinguishable from a detector that has stopped working.

## Three findings worth stealing

1. **Your "attack" is probably you.** The single loudest signal in a week here
   was our own WAN address: a phone app requesting thumbnails for deleted
   assets, 27 of 29 application-layer events. The big numbers in a CrowdSec
   `cscli metrics` dump are community blocklists, not traffic that reached
   you. Count *local* alerts before concluding anything.
2. **Percent-encoding defeats a naive WAF rule.** A rule matching
   `union select` never fires against `union%20select`. The Worker and the
   proposed WAF rule had the identical flaw; both now decode first. It looked
   correct in the dashboard and blocked nothing.
3. **An empty `200` is not a "no".** `GET /accounts` returning 200 with an
   empty result was read as "this token has no Workers access". Listing
   accounts needs its own permission. Probe the endpoint you actually care
   about — and to tell Read from Edit, probe a *write*.

## A published repo and the running copy drift silently

A fix made here on 2026-09-10 was never copied back to the machine actually
running it, so for eleven days the live copy could have edge-banned its own
WAN address. If you run this, run *this* — not a fork of it you patched once.

## Run it

```
cp warden.yml.example warden.yml      # then edit: put YOUR public IPs in allow
export WARDEN_LOG_HOST=user@loghost    # where the log containers live (SSH)
export CLOUDFLARE_API_TOKEN=...        # only needed once enforce: true
export CLOUDFLARE_ACCOUNT_ID=...
python3 warden.py                      # one sweep; wire to a 5-min timer
python3 warden-ui.py                   # dashboard on 127.0.0.1:8792

cp netscan.yml.example netscan.yml     # then edit: your networks, your critical hosts
python3 netscan.py                     # LAN discovery; wire to a 15-min timer
python3 netscan.py --ports             # slower TCP sweep; wire to a daily timer

export CF_API_TOKEN=...  CF_ZONE_ID=...
python3 cfsec.py --audit               # read-only
python3 cfsec.py --apply-waf           # dry run
python3 cfsec.py --apply-waf --commit  # writes

cd edge-sentry && node test.mjs        # 11 unit tests, no network needed
```

## Honest scope

This is a **working reference implementation, not a plug-and-play product.** The
collectors assume your logs are reachable by `ssh + docker exec` and know the
container names and paths of *my* setup — swap them for however yours are
reachable; they are ~10 lines each. And **read [KNOWN-ISSUES.md](KNOWN-ISSUES.md)
before you set `enforce: true`** — detect-only is the supported mode, and the
enforcement path has real caveats spelled out there.

It is a second opinion, not a replacement for CrowdSec or a WAF. It reads what
they miss.

---

## The write-up

Putting one identity provider in front of a whole self-hosted estate, and the
zero-cost mistakes that undid most of it — a field report, free if you want it:

**[Security First, Honestly →](https://asareanderson.gumroad.com/l/jlaeoh)** (pay what you want)

More field notes from the same estate: **[dev.to/c1-anderson](https://dev.to/c1-anderson)**
