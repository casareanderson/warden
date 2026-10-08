#!/usr/bin/env python3
"""netintel.py — whole-LAN DNS + connection threat intel for warden (built 2026-10-07). No LLM.

Vantage point = your router (reference: OpenWrt + AdGuard Home), reached read-only over SSH with a
dedicated key. Nothing runs ON the router (they rarely have RAM to spare).

Config (warden.yml):
  router.ssh        e.g. root@192.0.2.1 — unset → netintel records "no router configured" and exits 0
  router.key        SSH private key for it (optional)
  router.querylog   AdGuard Home query log (default /etc/AdGuardHome/data/querylog.json)
  estate.lan        your LAN CIDRs (default: any private address counts as LAN)

  netintel.py            pull new AdGuard query-log lines + one conntrack snapshot, match, alert (timer: 10 min)
  netintel.py --feeds    force-refresh the threat feeds (also refreshed automatically when > 20 h old)
  netintel.py --test     last 15 hits

Feeds (all free, cached in data/intel/, refused if a download looks truncated):
  domains: abuse.ch URLhaus hostfile (malware hosting), abuse.ch ThreatFox hostfile (malware/C2), OpenPhish feed (phishing)
  IPs:     abuse.ch Feodo Tracker (botnet C2), FireHOL level1 (bogons, Spamhaus DROP/EDROP, DShield top, Feodo, …)
Also flagged: any LAN device connecting to a redlist.yml `watch` country (DB-IP geo), and NXDOMAIN bursts
(≥150 failed lookups by one device in a run = DGA-style malware behaviour, or a broken app).
Alerts → the alert channel (wlib.notify), deduped per (device, indicator) for 12 h, device named from netscan's inventory.
"""
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geo import Geo  # noqa: E402
from wlib import config, notify  # noqa: E402

DB = config.DB
INTEL = str(config.DATA / "intel")


def ROUTER():  # noqa: N802
    key = config.get("router.key")
    return (["ssh"] + (["-i", key] if key else []) +
            ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
             config.get("router.ssh")])


def QLOG():  # noqa: N802
    return config.get("router.querylog") or "/etc/AdGuardHome/data/querylog.json"


FEEDS = {
    "urlhaus": ("domain", "https://urlhaus.abuse.ch/downloads/hostfile/", 100),
    "threatfox": ("domain", "https://threatfox.abuse.ch/downloads/hostfile/", 100),
    "openphish": ("domain", "https://openphish.com/feed.txt", 50),
    "feodo": ("ip", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 1),
    "firehol1": ("ip", "https://iplists.firehol.org/files/firehol_level1.netset", 1000),
}
NXDOMAIN_BURST = 150


def lan_nets():
    out = []
    for c in config.get("estate.lan") or []:
        try:
            out.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            pass
    return out


def in_lan(ip, nets=None):
    nets = lan_nets() if nets is None else nets
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nets) if nets else a.is_private


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.executescript("""
      create table if not exists watermarks(source text primary key, pos text);
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer,
        parsed integer, note text);
      create table if not exists intel_hits(
        id integer primary key, ts text, device text, device_name text, kind text, indicator text,
        feed text, detail text, notified integer default 0);
      create index if not exists ih_ts on intel_hits(ts);
    """)
    return con


# ── feeds ────────────────────────────────────────────────────────────────────
def refresh_feeds(force=False):
    os.makedirs(INTEL, exist_ok=True)
    for name, (_, url, min_lines) in FEEDS.items():
        path = f"{INTEL}/{name}.txt"
        if not force and os.path.exists(path) and time.time() - os.path.getmtime(path) < 20 * 3600:
            continue
        try:
            r = requests.get(url, timeout=60, headers={"User-Agent": "warden-netintel/1 (homelab)"})
            r.raise_for_status()
            lines = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
            if len(lines) < min_lines:
                print(f"feed {name}: only {len(lines)} lines — keeping the previous copy"); continue
            open(path + ".tmp", "w").write(r.text); os.replace(path + ".tmp", path)
        except Exception as e:  # noqa: BLE001 — a stale feed beats no feed; say so
            print(f"feed {name}: {type(e).__name__} — keeping the previous copy")


def load_feeds():
    domains, nets = {}, []
    for name, (kind, _, _) in FEEDS.items():
        path = f"{INTEL}/{name}.txt"
        if not os.path.exists(path):
            continue
        for l in open(path, errors="replace"):
            l = l.split("#")[0].strip()
            if not l:
                continue
            if kind == "domain":
                if name == "openphish":
                    m = re.match(r"https?://([^/:]+)", l)
                    host = m.group(1).lower() if m else ""
                else:
                    parts = l.split()
                    host = (parts[1] if len(parts) > 1 else parts[0]).lower()
                if host and host not in ("localhost", "0.0.0.0") and "." in host:
                    domains.setdefault(host, name)
            else:
                try:
                    nets.append((ipaddress.ip_network(l.split()[0], strict=False), name))
                except ValueError:
                    pass
    # never flag our own LAN / private ranges because a bogon list contains them
    lans = [x for x in lan_nets() if x.version == 4]
    nets = [(n, f) for n, f in nets if not (n.version == 4 and (any(n.overlaps(x) for x in lans) or n.is_private or n.is_reserved
                                                               or n.is_multicast or n.is_link_local or n.is_loopback))]
    v4 = sorted(((int(n.network_address), int(n.broadcast_address), f) for n, f in nets if n.version == 4))
    return domains, v4


def ip_in(v4, ip):
    import bisect
    try:
        x = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(v4, (x, float("inf"), "")) - 1
    while i >= 0 and v4[i][0] <= x:
        if x <= v4[i][1]:
            return v4[i][2]
        i -= 1
        if i >= 0 and x - v4[i][0] > 2 ** 24:      # ranges are at most /8 in practice; stop scanning back
            break
    return None


# ── sources ──────────────────────────────────────────────────────────────────
def pull_dns(con):
    wm = con.execute("select pos from watermarks where source='adguard'").fetchone()
    inode, off = (wm[0].split(":") + ["0"])[:2] if wm else ("", "0")
    st = subprocess.run(ROUTER() + [f"stat -c %i:%s {QLOG()}"], capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=30).stdout.strip()
    if not st:
        raise RuntimeError("AdGuard query log not readable on the router")
    cur, size = st.split(":")
    off = int(off) if cur == inode and int(off) <= int(size) else max(0, int(size) - 2_000_000)   # first run: last ~2 MB
    data = subprocess.run(ROUTER() + [f"tail -c +{off + 1} {QLOG()} | head -c 30000000"], capture_output=True, stdin=subprocess.DEVNULL,
                          timeout=180).stdout
    cut = data.rfind(b"\n")
    data = data[:cut + 1] if cut >= 0 else b""
    con.execute("insert or replace into watermarks(source,pos) values('adguard',?)", (f"{cur}:{off + len(data)}",))
    out = []
    for l in data.decode("utf-8", "replace").splitlines():
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def pull_conntrack():
    txt = subprocess.run(ROUTER() + ["cat /proc/net/nf_conntrack"], capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=60).stdout
    flows = set()
    lans = lan_nets()
    for l in txt.splitlines():
        m = re.search(r"src=(\S+) dst=(\S+) (?:sport=\d+ dport=(\d+))?", l)
        if not m:
            continue
        src, dst, dport = m.group(1), m.group(2), m.group(3) or ""
        try:
            # only real internet destinations: is_global excludes multicast (mDNS 224.0.0.251), CGNAT/NetBird
            # 100.64/10, link-local, reserved — all of which FireHOL's bogon blocks would otherwise "match"
            d = ipaddress.ip_address(dst)
            if in_lan(src, lans) and d.is_global and not (d.is_multicast or d.is_reserved):
                flows.add((src, dst, dport))
        except ValueError:
            pass
    return flows


def match_domain(host, domains):
    h = host.rstrip(".").lower()
    while h.count(".") >= 1:
        if h in domains:
            return h, domains[h]
        h = h.split(".", 1)[1]
    return None, None


def main():
    con = db()
    if "--test" in sys.argv:
        for r in con.execute("select ts,device,device_name,kind,indicator,feed,detail from intel_hits order by id desc limit 15"):
            print(r)
        return 0
    if not config.get("router.ssh"):
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'adguard',0,0,"
                    "'skipped: no router configured')")
        con.commit()
        print("netintel: no router configured (router.ssh) — nothing to do")
        return 0
    refresh_feeds("--feeds" in sys.argv)
    domains, v4 = load_feeds()
    names = {r[0]: (r[1] or r[2] or "") for r in con.execute("select ip, hostname, vendor from net_hosts")}
    try:
        import yaml
        watch = (yaml.safe_load(open(config.HOME / "redlist.yml")) or {}).get("watch") or {}
    except Exception:  # noqa: BLE001
        watch = {}
    geo = Geo()
    hits = []
    try:
        dns = pull_dns(con)
        nx = {}
        for q in dns:
            client, host = q.get("IP", ""), q.get("QH", "")
            hit, feed = match_domain(host, domains)
            if hit:
                blocked = bool((q.get("Result") or {}).get("IsFiltered"))
                hits.append((client, "dns", hit, feed, f"looked up {host}" + (" (AdGuard blocked it)" if blocked else
                                                                             " — NOT blocked by AdGuard")))
            if (q.get("Result") or {}).get("Rcode") == 3 or q.get("Rcode") == 3:
                nx[client] = nx.get(client, 0) + 1
        for client, n in nx.items():
            if n >= NXDOMAIN_BURST:
                hits.append((client, "nxdomain-burst", f"{n} NXDOMAIN", "heuristic",
                             f"{n} failed lookups in one run — DGA malware or a broken app"))
        dns_note = f"ok, {len(dns)} queries, {len(domains)} bad domains loaded"
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'adguard',?,?,?)",
                    (len(dns), sum(1 for h in hits if h[1] == "dns"), "ok"))
    except Exception as e:  # noqa: BLE001
        dns_note = f"BLIND: {e}"
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'adguard',0,0,?)", (dns_note[:200],))
    try:
        flows = pull_conntrack()
        for src, dst, dport in flows:
            feed = ip_in(v4, dst)
            if feed:
                hits.append((src, "flow-badip", dst, feed, f"connection to {dst}:{dport}"))
            cc = geo.cc(dst)
            if cc in watch:
                hits.append((src, "flow-redlist", f"{dst} ({cc})", "redlist", f"connection to {dst}:{dport} in {watch[cc]}"))
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'conntrack',?,?,'ok')",
                    (len(flows), sum(1 for h in hits if h[1].startswith("flow"))))
    except Exception as e:  # noqa: BLE001
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'conntrack',0,0,?)",
                    (f"BLIND: {e}"[:200],))
    loud = []
    for dev, kind, ind, feed, detail in hits:
        name = names.get(dev, "")
        con.execute("insert into intel_hits(ts,device,device_name,kind,indicator,feed,detail) values(?,?,?,?,?,?,?)",
                    (now(), dev, name, kind, ind, feed, detail))
        dup = con.execute("select 1 from intel_hits where device=? and indicator=? and notified=1 and "
                          "ts > datetime('now','-12 hours')", (dev, ind)).fetchone()
        if not dup:
            con.execute("update intel_hits set notified=1 where id=last_insert_rowid()")
            loud.append(f"**{name or dev}** ({dev}) — {kind}: `{ind}` [{feed}] {detail}")
    con.execute("delete from intel_hits where ts < datetime('now','-90 days')")
    con.commit()
    if loud:
        if not notify.send(("🧪 **Network threat intel** (router DNS + connections)\n" + "\n".join(loud[:15]))[:1990]):
            print("notify failed")
    print(f"netintel: dns {dns_note}; hits {len(hits)}, notified {len(loud)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
