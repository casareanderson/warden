"""Host health from Beszel — optional, off by default.

Beszel (https://github.com/henrygd/beszel) already collects CPU/RAM/disk/temperature from every machine and has its
own alert thresholds. warden doesn't rebuild that: with `beszel.enabled: true` it reads Beszel's verdict and shows
one "Host health" card (all OK, or which hosts are over a threshold / not reporting). Two ways in:

  beszel:
    enabled: true
    snapshot: /var/lib/beszel-snapshot/hosts.json    # A) file written by tools/beszel-snapshot.py on the hub box
    # url: http://beszel.lan:8090                    # B) the hub's API, as a Beszel user with the read-only role
    # user: warden@example.com
    # password_secret: BESZEL_PASSWORD               #    resolved through warden's secrets backend
    link: http://beszel.lan:8090                     # where "Open Beszel" points (defaults to url)
    stale_s: 300                                     # a host not seen for this long counts as not reporting
    ignore_hosts: []                                 # registered in Beszel but gone on purpose
    ignore_alerts: {}                                # e.g. {nas: [Disk]} for a read-only root that always reads 100%

Read-only either way: warden never writes to Beszel.
"""
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import config, secrets

TIMEOUT = 6


def _ts(s):
    """PocketBase '2026-10-11 10:15:31.981Z' or ISO '2026-10-11T10:15:31Z' → epoch seconds."""
    if not s:
        return None
    s = s.strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()


def _from_snapshot(path, stale_s, now):
    with open(path) as f:
        snap = json.load(f)
    gen = _ts(snap.get("generated"))
    if gen is None or now - gen > stale_s:
        raise RuntimeError(f"snapshot is {int(now - gen) if gen else '?'} s old — is the beszel-snapshot timer running?")
    hosts = [{"name": h["name"], "status": h.get("status"), "stale": bool(h.get("stale")), "alerts": list(h.get("alerts") or []),
              "cpu": h.get("cpu"), "mem_pct": h.get("mem_pct"), "disk_pct": h.get("disk_pct"), "temp_c": h.get("temp_c"),
              "last_seen": h.get("last_seen")} for h in snap.get("hosts", [])]
    return hosts, snap.get("generated")


def _get(url, token=None, data=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": token} if token else {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:     # noqa: S310 — URL comes from the owner's warden.yml
        return json.load(r)


def _from_api(c, stale_s, now):
    base = c["url"].rstrip("/")
    pw = secrets.get(c.get("password_secret") or "BESZEL_PASSWORD")
    if not (c.get("user") and pw):
        raise RuntimeError("beszel.user / the password secret is not set")
    tok = _get(f"{base}/api/collections/users/auth-with-password", data={"identity": c["user"], "password": pw})["token"]
    systems = _get(f"{base}/api/collections/systems/records?perPage=500&fields=id,name,status,updated,info", tok)["items"]
    flt = urllib.parse.quote("triggered=true")
    alerts = _get(f"{base}/api/collections/alerts/records?perPage=500&fields=system,name,triggered&filter={flt}", tok)["items"]
    hot = {}
    for a in alerts:
        if a.get("triggered"):
            hot.setdefault(a["system"], []).append(a["name"])
    hosts = []
    for s in systems:
        info = s.get("info") or {}
        last = _ts(s.get("updated"))
        hosts.append({"name": s["name"], "status": s.get("status"),
                      "stale": s.get("status") != "up" or last is None or now - last > stale_s,
                      "alerts": sorted(set(hot.get(s["id"], []))), "cpu": info.get("cpu"), "mem_pct": info.get("mp"),
                      "disk_pct": info.get("dp"), "temp_c": info.get("dt"), "last_seen": s.get("updated")})
    return hosts, datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")


def fetch(now=None):
    """None when the integration is off; otherwise {"hosts", "summary", "link", ...} or {"error": ...}."""
    c = config.get("beszel") or {}
    if not c.get("enabled"):
        return None
    now = now or time.time()
    stale_s = int(c.get("stale_s") or 300)
    out = {"enabled": True, "link": c.get("link") or c.get("url") or "", "source": "snapshot" if c.get("snapshot") else "api"}
    try:
        if c.get("snapshot"):
            hosts, gen = _from_snapshot(c["snapshot"], stale_s, now)
        elif c.get("url"):
            hosts, gen = _from_api(c, stale_s, now)
        else:
            raise RuntimeError("set beszel.snapshot or beszel.url")
    except Exception as e:  # noqa: BLE001 — a broken integration shows as an error on the card, never breaks the page
        return dict(out, error=f"{type(e).__name__}: {str(e)[:160]}", hosts=[], summary=None)
    hide, quiet = set(c.get("ignore_hosts") or []), c.get("ignore_alerts") or {}
    keep = []
    for h in hosts:
        if h["name"] in hide:
            continue
        h["alerts"] = [a for a in h["alerts"] if a not in set(quiet.get(h["name"], []))]
        h["state"] = "stale" if h["stale"] else "hot" if h["alerts"] else "ok"
        keep.append(h)
    keep.sort(key=lambda h: ({"stale": 0, "hot": 1, "ok": 2}[h["state"]], h["name"].lower()))
    n = {s: sum(1 for h in keep if h["state"] == s) for s in ("ok", "hot", "stale")}
    return dict(out, generated=gen, hosts=keep, hidden=sorted(hide),
                summary={"total": len(keep), **n,
                         "attention": [f"{h['name']}: " + (", ".join(h["alerts"]) if h["state"] == "hot" else "not reporting")
                                       for h in keep if h["state"] != "ok"]})
