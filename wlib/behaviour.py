"""Per-device behaviour: what each device in the house normally talks to (step 2 of the owner's 2026-10-10 ask).

Fed by netintel.py, which already pulls every DNS lookup from the router's AdGuard log. For each DEVICE (devices.py
identity, so a phone on rotating private addresses is still one device) it keeps the registrable domains it looks
up (`wiz.com`, not `eu-iot-03.wiz.com`), how often, and on how many separate days. No model is involved: these are
the facts that step 3's scoring and the Hermes `sec` review are given.

A device is LEARNING for its first LEARN_DAYS of observation; a domain that first appears after that is "new for
this device", which is what step 3 looks at — and only means something for fixed-function devices (a bulb, a plug,
a TV), whose normal is narrow. Phones and laptops look up new things all day.
"""
import re
import time

LEARN_DAYS = 7
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au", "org.au",
             "co.nz", "co.jp", "ne.jp", "com.br", "com.cn", "com.tw", "co.kr", "co.in", "com.sg", "com.hk", "co.za",
             "com.mx", "com.tr", "eu.org", "amazonaws.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com",
             "github.io", "pages.dev", "workers.dev", "appspot.com", "firebaseio.com", "blogspot.com"}


def registrable(host):
    """'eu-iot-03.wiz.com.' → 'wiz.com'; None for things that aren't internet names (local, reverse, service discovery)."""
    h = (host or "").rstrip(".").lower()
    if not h or "." not in h or h.endswith((".lan", ".local", ".arpa", ".home", ".internal", ".localdomain")) \
            or h.startswith("_") or re.fullmatch(r"[\d.]+", h):
        return None
    parts = h.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def schema(con):
    con.executescript("""
      create table if not exists dev_dns(identity text, domain text, first_seen text, last_seen text, hits integer,
        days integer, last_day text, primary key(identity, domain));
      create table if not exists dev_obs(identity text primary key, first_obs text, last_obs text);
      create index if not exists dev_dns_domain on dev_dns(domain);""")


def identities(con):
    """ip → device identity, from devices.py (latest row per ip). Unknown ips fall back to 'ip:<addr>'."""
    try:
        rows = con.execute("select ip, identity from devices where identity is not null order by last_seen").fetchall()
    except Exception:  # noqa: BLE001 — devices.py has not run yet
        return {}
    return {r[0]: r[1] for r in rows if r[0]}


def _when(q, ts):
    t = (q.get("T") or "")[:19].replace("T", " ")
    return t if len(t) == 19 else ts


def record(con, queries, ts=None):
    """Fold a batch of AdGuard query-log entries into the baselines, using each lookup's own time (so the router's
    week of history can be replayed in order — see backfill). Returns (#devices, #new (device, domain) pairs)."""
    schema(con)
    ts = ts or time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    who = identities(con)
    agg = {}                                  # (identity, domain, day) → [hits, first, last]
    for q in queries:
        ip, dom = q.get("IP", ""), registrable(q.get("QH", ""))
        if not ip or not dom:
            continue
        t = _when(q, ts)
        a = agg.setdefault((who.get(ip) or f"ip:{ip}", dom, t[:10]), [0, t, t])
        a[0] += 1; a[1] = min(a[1], t); a[2] = max(a[2], t)
    new, seen = 0, {}
    for (ident, dom, day), (n, t0, t1) in sorted(agg.items(), key=lambda x: x[0][2]):
        cur = con.execute("select last_day from dev_dns where identity=? and domain=?", (ident, dom)).fetchone()
        if cur:
            con.execute("update dev_dns set last_seen=max(last_seen, ?), hits=hits+?, days=days+?, last_day=max(last_day, ?) "
                        "where identity=? and domain=?", (t1, n, 1 if day > (cur[0] or "") else 0, day, ident, dom))
        else:
            con.execute("insert into dev_dns(identity, domain, first_seen, last_seen, hits, days, last_day) "
                        "values(?,?,?,?,?,1,?)", (ident, dom, t0, t1, n, day))
            new += 1
        s0, s1 = seen.get(ident, (t0, t1)); seen[ident] = (min(s0, t0), max(s1, t1))
    for ident, (t0, t1) in seen.items():
        con.execute("insert into dev_obs(identity, first_obs, last_obs) values(?,?,?) on conflict(identity) do update set "
                    "first_obs=min(first_obs, excluded.first_obs), last_obs=max(last_obs, excluded.last_obs)", (ident, t0, t1))
    return len(seen), new


def backfill(con, lines_iter, batch=50000):
    """Replay the router's existing query log (oldest file first) so baselines start full instead of blind."""
    import json
    buf, total, pairs = [], 0, 0
    for ln in lines_iter:
        try:
            buf.append(json.loads(ln))
        except ValueError:
            continue
        if len(buf) >= batch:
            pairs += record(con, buf)[1]; total += len(buf); buf = []; con.commit()
    if buf:
        pairs += record(con, buf)[1]; total += len(buf); con.commit()
    return total, pairs


def learning(con, ident):
    r = con.execute("select julianday('now') - julianday(first_obs) from dev_obs where identity=?", (ident,)).fetchone()
    return r is None or r[0] < LEARN_DAYS


def profile(con, ident, limit=40):
    """What one device normally talks to, most-used first — for the console, the API/MCP and the Hermes review."""
    schema(con)
    obs = con.execute("select first_obs, last_obs from dev_obs where identity=?", (ident,)).fetchone()
    doms = con.execute("select domain, hits, days, first_seen, last_seen from dev_dns where identity=? "
                       "order by days desc, hits desc limit ?", (ident, limit)).fetchall()
    return {"identity": ident, "first_obs": obs[0] if obs else None, "learning": learning(con, ident),
            "domains": [dict(zip(("domain", "hits", "days", "first_seen", "last_seen"), d)) for d in doms]}
