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

## Run it

```
cp warden.yml.example warden.yml      # then edit: put YOUR public IPs in allow
export WARDEN_LOG_HOST=user@loghost    # where the log containers live (SSH)
export CLOUDFLARE_API_TOKEN=...        # only needed once enforce: true
export CLOUDFLARE_ACCOUNT_ID=...
python3 warden.py                      # one sweep; wire to a 5-min timer
python3 warden-ui.py                   # dashboard on 127.0.0.1:8792
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
