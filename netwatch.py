#!/usr/bin/env python3
"""netwatch.py — is the internet working, and if not, is it us or the ISP? (owner 2026-10-10: "figure out internet blip")

On 2026-10-10 lookups to EVERY outside DNS provider went slow for ~90 minutes (80% over 2 s, some 36 s) while the
router's local lookups stayed fast — so the line or something on it, not DNS. Nothing was recording line usage, so
the cause could not be pinned. This records, once a minute:

  router    ping the LAN gateway (is the house network itself OK?)
  internet  ping two public resolvers (loss, latency)
  dns       one uncached lookup via the router, one straight to a public resolver
  web       one HTTPS fetch (a tiny 204 page)
  line      the router's internet-port byte counters → Mbit/s in and out since the last sample (router.ssh, read-only)
  top       when the minute is bad: the LAN devices with the most bytes on open connections (who is filling the line)

A minute is "degraded" when internet loss ≥ 20%, either lookup is slower than 2 s, or the fetch takes > 3 s; "down"
when nothing outside answers at all. Three bad minutes in a row → one message (how bad, how full the line is, who is
using it); recovery → one message with how long it lasted. No model, read-only.

  netwatch.py            take one sample (timer: every minute)
  netwatch.py --last 30  print the last N samples
"""
import json, random, re, sqlite3, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wlib import config, notify  # noqa: E402

PUBLIC = ["1.1.1.1", "8.8.8.8"]
BAD_FOR = 3


def sh(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, ""


def ping(host, n=3):
    rc, out = sh(["ping", "-n", "-q", "-c", str(n), "-W", "2", host], timeout=n * 3 + 5)
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", out)
    return (float(loss.group(1)) if loss else 100.0), (float(rtt.group(1)) if rtt else None)


def dig(server):
    name = f"nw{random.randint(10**6, 10**7)}.example.com"           # random label → never cached anywhere
    t = time.time()
    rc, out = sh(["dig", "+tries=1", "+time=5", f"@{server}", name, "+noall", "+comments"], timeout=8)
    ok = rc == 0 and "status:" in out                                 # NXDOMAIN is a fine, complete answer
    return round((time.time() - t) * 1000) if ok else None


def https():
    rc, out = sh(["curl", "-s", "-o", "/dev/null", "-m", "8", "-w", "%{http_code} %{time_total}",
                  "https://www.google.com/generate_204"], timeout=10)
    try:
        code, tt = out.split()
        return round(float(tt) * 1000) if code == "204" else None
    except ValueError:
        return None


def router(cmd):
    key = config.get("router.key")
    return sh(["ssh"] + (["-i", key] if key else []) + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
              config.get("router.ssh"), cmd], timeout=20)


def line_counters():
    """(rx_bytes, tx_bytes) of the router's internet port (the default-route device)."""
    if not config.get("router.ssh"):
        return None
    rc, out = router("dev=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i==\"dev\") print $(i+1)}' | head -1); "
                     "grep \"^ *$dev:\" /proc/net/dev")
    m = re.match(r"\s*\S+:\s*(\d+)(?:\s+\d+){7}\s+(\d+)", out or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def top_talkers(n=3):
    rc, out = router("cat /proc/net/nf_conntrack")
    by = {}
    for ln in (out or "").splitlines():
        src = re.search(r"src=(\S+)", ln); b = sum(int(x) for x in re.findall(r"bytes=(\d+)", ln))
        if src and re.match(r"(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", src.group(1)):
            by[src.group(1)] = by.get(src.group(1), 0) + b
    names = {}
    try:
        con = sqlite3.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=10)
        names = {r[0]: r[1] for r in con.execute("select ip, name from devices order by last_seen")}
    except sqlite3.Error:
        pass
    return [f"{names.get(ip, ip)} ({ip}) {b / 1e6:.0f} MB" for ip, b in sorted(by.items(), key=lambda x: -x[1])[:n] if b > 1e6]


def db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.execute("""create table if not exists net_health(ts real, gw_loss real, gw_ms real, wan_loss real, wan_ms real,
                   dns_router_ms integer, dns_direct_ms integer, https_ms integer, rx_bytes integer, tx_bytes integer,
                   rx_mbps real, tx_mbps real, state text, top text)""")
    con.execute("create table if not exists net_incidents(id integer primary key, started real, ended real, worst text, "
                "message_id text)")
    return con


def sample():
    con = db(); now = time.time()
    gw = config.get("netwatch.gateway") or (config.get("router.ssh") or "@").split("@")[-1]
    gw_loss, gw_ms = ping(gw) if gw else (None, None)
    pubs = [ping(h) for h in PUBLIC]
    wan_loss = min(p[0] for p in pubs); wan_ms = min((p[1] for p in pubs if p[1] is not None), default=None)
    d_router, d_direct, web = dig(gw) if gw else None, dig(PUBLIC[1]), https()
    lc = line_counters(); rx = tx = None
    prev = con.execute("select ts, rx_bytes, tx_bytes from net_health where rx_bytes is not null order by ts desc limit 1").fetchone()
    if lc and prev and lc[0] >= prev[1] and now - prev[0] < 600:
        rx = round((lc[0] - prev[1]) * 8 / (now - prev[0]) / 1e6, 1); tx = round((lc[1] - prev[2]) * 8 / (now - prev[0]) / 1e6, 1)
    down = wan_loss >= 100 and web is None
    bad = down or wan_loss >= 20 or d_router is None or d_router > 2000 or (d_direct or 9999) > 2000 or web is None or web > 3000
    state = "down" if down else "degraded" if bad else "ok"
    top = top_talkers() if bad and config.get("router.ssh") else []
    con.execute("insert into net_health values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (now, gw_loss, gw_ms, wan_loss, wan_ms, d_router, d_direct, web, lc[0] if lc else None,
                 lc[1] if lc else None, rx, tx, state, json.dumps(top)))
    con.execute("delete from net_health where ts < ?", (now - 30 * 86400,))
    con.commit()                                       # commit BEFORE any notify call (patcher reply-loop lesson)
    incident(con, now, state, dict(gw_loss=gw_loss, wan_loss=wan_loss, wan_ms=wan_ms, d_router=d_router, d_direct=d_direct,
                                   web=web, rx=rx, tx=tx, top=top))
    print(f"netwatch: {state} gw {gw_loss}%/{gw_ms}ms · internet {wan_loss}%/{wan_ms}ms · dns router {d_router} direct "
          f"{d_direct} ms · web {web} ms · line ↓{rx} ↑{tx} Mbit/s" + (f" · top {top}" if top else ""))


def incident(con, now, state, f):
    open_inc = con.execute("select id, started, message_id from net_incidents where ended is null").fetchone()
    recent = [r[0] for r in con.execute("select state from net_health order by ts desc limit ?", (BAD_FOR,))]
    if not open_inc and len(recent) == BAD_FOR and all(s != "ok" for s in recent):
        started = con.execute("select min(ts) from (select ts from net_health order by ts desc limit ?)", (BAD_FOR,)).fetchone()[0]
        who = ("; busiest: " + ", ".join(f["top"])) if f["top"] else ""
        line = f"line ↓{f['rx']} ↑{f['tx']} Mbit/s" if f["rx"] is not None else "line usage unknown"
        local = "the house network is fine (router answers)" if (f["gw_loss"] or 0) < 20 else "⚠️ the ROUTER itself is not answering well"
        msg = (f"🌐 **Internet {'DOWN' if state == 'down' else 'degraded'}** since {time.strftime('%H:%M', time.localtime(started))}: "
               f"loss {f['wan_loss']:.0f}%, DNS via router {f['d_router'] or 'timeout'} ms / direct {f['d_direct'] or 'timeout'} ms, "
               f"web {f['web'] or 'failed'} ms. {local}; {line}{who}.")
        con.execute("insert into net_incidents(started, worst) values(?,?)", (started, json.dumps(f))); con.commit()
        mid = notify.send(msg)
        con.execute("update net_incidents set message_id=? where ended is null", (str(mid),)); con.commit()
    elif open_inc and state == "ok":
        mins = round((now - open_inc[1]) / 60)
        con.execute("update net_incidents set ended=? where id=?", (now, open_inc[0])); con.commit()
        notify.send(f"🌐 Internet back to normal after about {mins} min.")


if __name__ == "__main__":
    if "--last" in sys.argv:
        n = int(sys.argv[sys.argv.index("--last") + 1])
        for r in db().execute("select * from net_health order by ts desc limit ?", (n,)):
            print(time.strftime("%H:%M:%S", time.localtime(r[0])), r[12], f"internet {r[3]}%/{r[4]}ms", f"dns {r[5]}/{r[6]}",
                  f"web {r[7]}", f"↓{r[10]} ↑{r[11]}", r[13])
    else:
        sample()
