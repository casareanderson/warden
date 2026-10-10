"""Everything the console, the REST API and the MCP connector read — one definition of each view.

Read-only: every query opens SQLite in `mode=ro`. Writes (layout, tokens, approvals)
live in their own modules and touch only their own tables.
"""
import json
import sqlite3
import sys
import threading
import time

from . import config

sys.path.insert(0, str(config.HOME))
from geo import Geo  # noqa: E402

GEO = Geo()
REDLIST = config.HOME / "redlist.yml"
if not REDLIST.exists():                     # ship the curated example until the owner edits a copy
    REDLIST = config.HOME / "redlist.yml.example"
SELF_IPS = config.HOME / "self-ips.txt"
# What counts as the edge STOPPING something. link_maze_injected (AI Labyrinth decoy links) and
# log/skip are informational — in one measured week they were 290 of 295 rows, most of them our own monitoring.
STOPPED = ("block", "managed_challenge", "challenge", "jschallenge", "drop", "connection_close")


def self_nets():
    """Our own addresses: self-ips.txt + warden.yml allow (single IPs or CIDRs)."""
    import ipaddress
    raw = []
    try:
        raw += [l.split("#")[0].strip() for l in SELF_IPS.read_text().splitlines()]
    except OSError:
        pass
    raw += [str(x) for x in (config.get("allow") or [])]
    out = []
    for r in raw:
        try:
            out.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            pass
    return out


def is_self(ip, nets):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets if n.version == a.version)
    except ValueError:
        return False


def q(sql, args=()):
    con = sqlite3.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, args)]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):        # intel.py has not run yet — empty, not a crash
            return []
        raise
    finally:
        con.close()


def accepted_exposure():
    """Exposure the owner decided to keep, with the reason: warden.yml cloudflare.sso_exempt + console accepts."""
    out = dict(config.get("cloudflare.sso_exempt") or {})
    try:
        out.update(json.loads((config.DATA / "accepted-exposure.json").read_text()))
    except (OSError, ValueError):
        pass
    return out


def redlist():
    """watch = flagged red; block = what the edge rule drops. The console switch (data/geo-block.json) wins over
    redlist.yml `block:`; geo-applied.json is what cfsec last pushed (fresher than the hourly snapshot)."""
    try:
        import yaml
        d = yaml.safe_load(REDLIST.read_text()) or {}
    except Exception:  # noqa: BLE001
        d = {}
    block, enabled, want = d.get("block") or [], bool(d.get("block")), None
    try:
        want = json.loads((config.DATA / "geo-block.json").read_text())
        block, enabled = want.get("block") or [], bool(want.get("enabled"))
    except (OSError, ValueError):
        pass
    try:
        done = json.loads((config.DATA / "geo-applied.json").read_text())
    except (OSError, ValueError):
        done = None
    pend = bool(want) and (not done or (config.DATA / "geo-block.json").stat().st_mtime >
                           (config.DATA / "geo-applied.json").stat().st_mtime)
    return {"watch": d.get("watch") or {}, "block": [str(c).upper() for c in block] if enabled else [],
            "chosen": [str(c).upper() for c in block], "enabled": enabled,
            "pending": pend, "applied": done, "checked": d.get("source_checked", "")}


def enforce_mode():
    return "enforcing" if config.get("enforce") else "detect-only"


def tag(rows, red, nets=None):
    nets = self_nets() if nets is None else nets
    for r in rows:
        r["self"] = is_self(r.get("ip", ""), nets)
        if "cc" not in r or not r.get("cc"):
            r["cc"] = GEO.cc(r.get("ip", ""))
        r["red"] = r["cc"] in red
    return rows


def _not_self(sql, args, limit, red, page=500, max_rows=50000):
    """Newest-first rows of `sql` (must end `order by id desc limit ? offset ?`) with our own addresses dropped.
    Pages instead of over-fetching once: a monitoring flood can be thousands of rows newer than the real ones.
    Returns (rows, how many own-address rows were skipped)."""
    nets, out, skipped, off = self_nets(), [], 0, 0
    while len(out) < limit and off < max_rows:
        chunk = tag(q(sql, list(args) + [page, off]), red, nets)
        for r in chunk:
            if r["self"]:
                skipped += 1
            elif len(out) < limit:
                out.append(r)
        if len(chunk) < page:
            break
        off += page
    return out, skipped


def _daily(rows):
    out = {}
    for r in rows:
        d = out.setdefault(r["ts"][:10], {"d": r["ts"][:10], "n": 0, "s": 0})
        d["n"] += 1
        d["s"] += r["score"] or 0
    return [out[k] for k in sorted(out)]


_CACHE = {"at": 0.0, "data": None}
_CACHE_LOCK = threading.Lock()
CACHE_SECONDS = 45


def payload_cached(max_age=CACHE_SECONDS):
    """payload(), at most `max_age` s old. A cold build measured 8.9 s (100 MB db on a busy HDD), warm 0.3 s —
    so the console keeps one warm copy (see warm_cache) and drops it on every write (invalidate)."""
    with _CACHE_LOCK:
        if _CACHE["data"] is None or time.time() - _CACHE["at"] > max_age:
            _CACHE["data"], _CACHE["at"] = payload(), time.time()
        return _CACHE["data"]


def invalidate():
    with _CACHE_LOCK:
        _CACHE["data"] = None


def warm_cache(every=CACHE_SECONDS - 15):
    """Background loop: rebuild before the copy expires, so a browser never waits on a cold build."""
    def loop():
        while True:
            try:
                with _CACHE_LOCK:
                    _CACHE["data"], _CACHE["at"] = payload(), time.time()
            except Exception as e:  # noqa: BLE001 — a failed warm-up must not kill the console
                print("warden-ui: cache warm failed:", e, flush=True)
            time.sleep(every)
    threading.Thread(target=loop, daemon=True, name="payload-warm").start()


def payload():
    red = redlist()
    watch = red["watch"]
    surf = q("select ts, data from surface_snap order by id desc limit 1")
    surface = json.loads(surf[0]["data"]) if surf else None
    if surface:
        surface["snap_ts"] = surf[0]["ts"]

    ev_all = tag(q("select ts, ip, source, kind, score from events where ts > datetime('now','-30 days')"), watch)
    edge_all = tag(q("select ip, cc, action, source, host from edge_events where ts > datetime('now','-30 days')"), watch)
    edge7 = [r for r in edge_all if not r["self"]]                      # our own monitoring is not an attack
    ev7 = [r for r in ev_all if not r["self"]]                          # measured 10-10: 97% of a day was our WAN IP
    day_ago = q("select datetime('now','-24 hours') t")[0]["t"]

    def count(rows, key, split=False):
        out = {}
        for r in rows:
            vals = (r[key] or "—").split(",") if split else [r[key] or "—"]
            for v in vals:
                if v != "unattributed":
                    out[v] = out.get(v, 0) + 1
        return sorted(({"k": k, "n": n} for k, n in out.items()), key=lambda x: -x["n"])

    countries = {}
    for r in ev7 + edge7:
        if r["cc"]:
            c = countries.setdefault(r["cc"], {"cc": r["cc"], "log": 0, "edge": 0, "ips": set()})
            c["edge" if "action" in r else "log"] += 1
            c["ips"].add(r["ip"])
    geo = sorted(({"cc": c["cc"], "log": c["log"], "edge": c["edge"], "ips": len(c["ips"]),
                   "red": c["cc"] in watch, "name": watch.get(c["cc"], ""), "blocked": c["cc"] in red["block"]}
                  for c in countries.values()), key=lambda x: -(x["log"] + x["edge"]))

    waf = (surface or {}).get("waf", [])
    country_rule = next((w for w in waf if "country" in (w.get("expr") or "")), None)
    done = red.get("applied")
    snap = ((surface or {}).get("ts") or "").replace("T", " ")[:19]      # both UTC, compared as text
    if done and done.get("ok") and done.get("ts", "") > snap:
        # the switch was applied after the last hourly snapshot: trust the read-back, not the stale snapshot
        country_rule = {"desc": "warden: block red-list countries", "expr": done["expression"]} if done["expression"] else None
    findings = (surface or {}).get("findings", [])
    acc = accepted_exposure()
    for f in findings:                        # an accept made since the hourly snapshot shows straight away
        if not f.get("accepted") and f.get("host") in acc:
            f["accepted"] = acc[f["host"]]

    top = [r for r in tag(q("select ip, sum(score) score, count(*) n, group_concat(distinct kind) kinds, "
                            "max(ts) last from events where ip!='' and ts > datetime('now','-30 days') "
                            "group by ip order by score desc limit 100"), watch) if not r["self"]][:25]

    return {
        "mode": enforce_mode(),
        "kpi": {
            "events_24h": sum(1 for r in ev7 if r["ts"] > day_ago),
            "events_self_24h": sum(1 for r in ev_all if r["self"] and r["ts"] > day_ago),
            "events_7d": len(ev7),
            "ips_7d": len({r["ip"] for r in ev7 if r["ip"]}),
            "edge_24h": sum(1 for r in tag(q("select ip, action from edge_events where ts > datetime('now','-24 hours')"), watch)
                            if r["action"] in STOPPED and not r["self"]),
            "edge_self_30d": sum(1 for r in edge_all if r["self"]),
            "red_hits_7d": sum(1 for r in ev7 + edge7 if r["red"]),
            "findings_open": sum(1 for f in findings if "accepted" not in f),
            "findings_high": sum(1 for f in findings if f["sev"] == "high" and "accepted" not in f),
            "hosts": q("select count(*) n from net_hosts")[0]["n"],
            "ports": q("select count(*) n from net_ports")[0]["n"],
            "bans": q("select count(*) n from bans where state in ('proposed','active')")[0]["n"],
        },
        "charts": {
            "kind": count(ev7, "kind", split=True)[:8],
            "source": count(ev7, "source"),
            "country": [{"k": g["cc"], "n": g["log"] + g["edge"], "red": g["red"]} for g in geo][:8],
            "edge_action": count(edge7, "action"),
            "net_alerts": q("select kind k, count(*) n from net_alerts where ts > datetime('now','-30 days') "
                            "group by kind order by n desc"),
            "surface_kind": count((surface or {}).get("hosts", []), "kind"),
        },
        "timeline": _daily(ev7),
        "edge_timeline": q("select strftime('%Y-%m-%d %H:00', ts) d, count(*) n from edge_events "
                           "where ts > datetime('now','-48 hours') group by d order by d")
        if q("select name from sqlite_master where name='edge_events'") else [],
        "bans": tag(q("select ts,ip,score,reasons,state,note from bans order by id desc limit 50"), watch),
        # edge blocklist (edgeban.py): owner ✅ in Discord → one Cloudflare WAF rule
        "edge_bans": [dict(r, cc=GEO.cc(r["target"].split("/")[0])) for r in
                      q("select target,reason,status,created,decided,expires,note,message_id from edge_bans "
                        "order by id desc limit 100")],
        "top": top,
        "recent": _not_self("select ts,source,ip,kind,detail,score from events order by id desc limit ? offset ?",
                            (), 100, watch)[0],
        "edge": tag(q("select ts,ip,cc,action,source,host,path,ua,rule from edge_events order by id desc limit 200"),
                    watch) if q("select name from sqlite_master where name='edge_events'") else [],
        "geo": geo,
        "redlist": {**red, "rule": country_rule},
        "surface": surface,
        "health": q("select source, max(ts) last_run, sum(lines) lines, sum(parsed) scored, "
                    "(select note from runs r2 where r2.source=runs.source order by id desc limit 1) note "
                    "from runs where ts > datetime('now','-24 hours') group by source"),
        "unattributed": q("select count(*) n from events where ip=''")[0]["n"],
        "net_alerts": q("select ts,kind,mac,ip,detail from net_alerts order by id desc limit 200"),
        "net_hosts": q("select mac,ip,hostname,vendor,first_seen,last_seen,approved from net_hosts "
                       "order by cast(replace(ip,'.','') as integer)"),
        "net_runs": q("select ts last_run, hosts from net_runs order by id desc limit 1"),  # latest sweep (summing an hour gave 4,689)
        "net_ports": q("select h.ip, h.hostname, h.vendor, count(*) n, "
                       "group_concat(np.port || '/' || coalesce(np.service,''), ', ') ports "
                       "from net_ports np join net_hosts h on h.mac = np.mac "
                       "group by h.mac order by n desc"),
        "suppressed": q("select ts,kind,detail,reason from alert_suppressed order by id desc limit 50"),
        "vuln": vuln_payload(),
        "endpoints": endpoints_payload(),
        "netsec": netsec_payload(),
    }


def has(t):
    return bool(q("select name from sqlite_master where name=?", (t,)))


def endpoints_payload():
    out = {"integrity": [], "findings": [], "harden": []}
    if has("integ_runs"):
        names = {r["target"]: r["name"] for r in q("select target, name from vuln_targets")} if has("vuln_targets") else {}
        out["integrity"] = [dict(r, name=names.get(r["target"], r["target"]),
                                 open=q("select count(*) n from integ_find where target=? and status='open'",
                                        (r["target"],))[0]["n"]) for r in q("select * from integ_runs order by target")]
        out["findings"] = q("select id,ts,target,kind,change,item,old,new,status,note from integ_find "
                            "order by (status='open') desc, id desc limit 200")
    if has("harden"):
        out["harden"] = q("select target,name,ts,idx,prev_idx,tests,warnings,suggestions,status,note from harden "
                          "order by idx")
    return out


def netsec_payload():
    out = {"ids_top": [], "ids_recent": [], "intel": [], "intel_by_device": [], "ids_24h": 0, "intel_24h": 0}
    if has("ids_alerts"):
        out["ids_top"] = q("select signature k, count(*) n, max(severity) sev, max(ts) last from ids_alerts "
                           "where ts > datetime('now','-7 days') group by signature order by n desc limit 12")
        out["ids_recent"] = q("select ts,severity,signature,category,src,sport,dst,dport,proto,app,cc from ids_alerts "
                              "order by id desc limit 150")
        out["ids_24h"] = q("select count(*) n from ids_alerts where ts > datetime('now','-24 hours')")[0]["n"]
    if has("intel_hits"):
        out["intel"] = q("select ts,device,device_name,kind,indicator,feed,detail from intel_hits "
                         "where kind!='false-positive' order by id desc limit 150")
        out["intel_by_device"] = q("select coalesce(nullif(device_name,''),device) k, count(*) n from intel_hits "
                                   "where kind!='false-positive' and ts > datetime('now','-7 days') group by k "
                                   "order by n desc limit 8")
        out["intel_24h"] = q("select count(*) n from intel_hits where kind!='false-positive' and "
                             "ts > datetime('now','-24 hours')")[0]["n"]
    return out


SEV = "case severity when 'CRITICAL' then 4 when 'HIGH' then 3 when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end"


def vuln_payload():
    if not q("select name from sqlite_master where name='vuln_targets'"):
        return None
    return {
        "targets": q("select * from vuln_targets order by n_kev desc, n_crit_fix desc, n_fixable desc, target"),
        # what matters: known-exploited anywhere, or anything with a fix — ranked KEV > severity > reach
        "top": q(f"select vid, max({SEV}) sev, max(kev) kev, count(distinct target) n_targets, "
                 "group_concat(distinct target) targets, group_concat(distinct pkg) pkgs, max(fixed) fixed, "
                 "max(title) title from vulns where fixed!='' or kev=1 group by vid "
                 f"order by kev desc, sev desc, n_targets desc limit 400"),
        "sev_fixable": q("select severity k, count(*) n from vulns where fixed!='' group by severity order by n desc"),
        "by_target": q("select t.name k, t.n_fixable n from vuln_targets t where t.n_fixable>0 order by n desc limit 8"),
        "totals": q(f"select count(*) total, sum(fixed!='') fixable, sum(fixed!='' and severity='CRITICAL') crit, "
                    "count(distinct case when kev=1 then vid end) kev from vulns")[0],
        "images": q("select * from img_advice order by kev desc, crit_fix desc, (action!='manual') desc")
        if has("img_advice") else [],
        "jobs": q("select id,target,name,status,requested_by,requested,n_pkgs,n_remove,before_fix,after_fix,reboot,"
                  "snapshot,finished,result,timing,run_after,timing_why from patch_jobs order by id desc limit 30")
        if q("select name from sqlite_master where name='patch_jobs'") else [],
    }


FIELDS = {"ip", "cc", "kind", "src", "host", "type"}


def search(text):
    """Unified search. Every row: ts, type, source, ip, cc, kind, detail, score."""
    terms, free = {}, []
    for t in (text or "").split():
        k, sep, v = t.partition(":")
        if sep and k.lower() in FIELDS and v:
            terms[k.lower()] = v.lower()
        else:
            free.append(t.lower())
    watch = redlist()["watch"]
    rows = []
    rows += [dict(r, type="log") for r in q(
        "select ts, source, ip, kind, detail, score from events order by id desc limit 5000")]
    if q("select name from sqlite_master where name='edge_events'"):
        rows += [{"ts": r["ts"], "type": "edge", "source": r["source"], "ip": r["ip"], "cc": r["cc"],
                  "kind": r["action"], "detail": f"{r['host']}{r['path']}  ua={r['ua'][:60]}  rule={r['rule']}",
                  "score": None, "host": r["host"]}
                 for r in q("select * from edge_events order by id desc limit 5000")]
    rows += [{"ts": r["last_seen"], "type": "host", "source": "netscan", "ip": r["ip"], "kind": "lan-host",
              "detail": f"{r['hostname'] or ''} {r['vendor'] or ''} {r['mac']}", "score": None}
             for r in q("select * from net_hosts")]
    rows += [{"ts": r["ts"], "type": "net-alert", "source": "netscan", "ip": r["ip"], "kind": r["kind"],
              "detail": f"{r['detail'] or ''} {r['mac'] or ''}", "score": None}
             for r in q("select * from net_alerts order by id desc limit 3000")]
    if q("select name from sqlite_master where name='vulns'"):
        rows += [{"ts": r["last_scan"], "type": "vuln", "source": r["name"], "ip": "", "kind": r["severity"],
                  "detail": f"{r['vid']} {r['pkg']} {r['installed']} → {r['fixed'] or 'no fix'}"
                            f"{' KEV' if r['kev'] else ''} {r['image'] or ''} {r['target']}", "score": None}
                 for r in q("select v.*, t.name, t.last_scan from vulns v join vuln_targets t using(target) "
                            "where v.fixed!='' or v.kev=1 limit 20000")]
    if has("ids_alerts"):
        rows += [{"ts": r["ts"], "type": "ids", "source": "suricata", "ip": r["src"], "kind": f"sev{r['severity']}",
                  "detail": f"{r['signature']} {r['src']}:{r['sport']}→{r['dst']}:{r['dport']} {r['app'] or r['proto']}",
                  "score": None} for r in q("select * from ids_alerts order by id desc limit 5000")]
    if has("intel_hits"):
        rows += [{"ts": r["ts"], "type": "intel", "source": r["feed"], "ip": r["device"], "kind": r["kind"],
                  "detail": f"{r['device_name']} {r['indicator']} {r['detail']}", "score": None}
                 for r in q("select * from intel_hits where kind!='false-positive' order by id desc limit 5000")]
    tag(rows, watch)
    out = []
    for r in rows:
        hay = " ".join(str(v) for v in r.values() if v is not None).lower()
        if terms.get("ip") and not (r.get("ip") or "").startswith(terms["ip"]):
            continue
        if terms.get("cc") and (r.get("cc") or "").lower() != terms["cc"]:
            continue
        if terms.get("kind") and terms["kind"] not in (r.get("kind") or "").lower():
            continue
        if terms.get("src") and terms["src"] not in (r.get("source") or "").lower():
            continue
        if terms.get("type") and terms["type"] != r["type"]:
            continue
        if terms.get("host") and terms["host"] not in hay:
            continue
        if all(f in hay for f in free):
            out.append(r)
    out.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return {"q": text, "total": len(out), "rows": out[:500]}


# ── home-page layout ─────────────────────────────────────────────────────────
# Every chart in the console can be pinned to the Overview. `src` is where the
# browser finds the data in /api's payload; `q` is the search a slice opens.
WIDGETS = {
    "kind":      {"title": "Detections by type", "type": "donut", "src": "charts.kind", "unit": "detections", "q": "kind:"},
    "source":    {"title": "By source", "type": "donut", "src": "charts.source", "unit": "events", "q": "src:"},
    "country":   {"title": "By country", "type": "donut", "src": "charts.country", "unit": "located", "q": "cc:"},
    "edge":      {"title": "Edge actions (Cloudflare)", "type": "donut", "src": "charts.edge_action", "unit": "edge events",
                  "q": "type:edge kind:"},
    "lan":       {"title": "LAN alerts · 30 days", "type": "donut", "src": "charts.net_alerts", "unit": "alerts",
                  "q": "type:net-alert kind:"},
    "vsev":      {"title": "Fixable CVEs by severity", "type": "donut", "src": "vuln.sev_fixable", "unit": "fixable",
                  "q": "type:vuln kind:"},
    "vbox":      {"title": "Fixable CVEs by box", "type": "donut", "src": "vuln.by_target", "unit": "fixable"},
    "ids":       {"title": "IDS alerts by signature · 7 d", "type": "donut", "src": "netsec.ids_top", "unit": "alerts",
                  "q": "type:ids "},
    "intel":     {"title": "Threat-intel hits by device · 7 d", "type": "donut", "src": "netsec.intel_by_device",
                  "unit": "hits"},
    "surfkind":  {"title": "Public names by kind", "type": "donut", "src": "charts.surface_kind", "unit": "names"},
    "tl30":      {"title": "Log detections · 30 days", "type": "timeline", "src": "timeline", "days": 30, "size": 2},
    "tledge":    {"title": "Edge events · 48 h", "type": "timeline", "src": "edge_timeline", "days": 0, "size": 2},
    "findings":  {"title": "Open attack-surface findings", "type": "findings", "size": 2},
    "approvals": {"title": "Waiting for your decision", "type": "approvals", "size": 2},
    "top":       {"title": "Top addresses · 30 days", "type": "top", "size": 4},
}
KPIS = ["events_24h", "ips_7d", "edge_24h", "red_hits_7d", "findings_open", "bans", "hosts", "vuln_kev", "vuln_fixable",
        "ids_24h", "integrity_open", "approvals"]
DEFAULT_LAYOUT = {"kpis": ["events_24h", "ips_7d", "edge_24h", "red_hits_7d", "findings_open", "bans", "hosts"],
                  "widgets": ["kind", "source", "country", "edge", "tl30", "findings", "top"]}


def _rw():
    con = sqlite3.connect(config.DB, timeout=30)
    con.execute("create table if not exists ui_settings(k text primary key, v text, updated text)")
    return con


def layout():
    """Saved layout, else warden.yml `dashboard.widgets`, else the default. Unknown ids are dropped,
    so a widget removed in a later version cannot break the page."""
    saved = None
    try:
        with _rw() as con:
            r = con.execute("select v from ui_settings where k='layout'").fetchone()
        saved = json.loads(r[0]) if r else None
    except (sqlite3.Error, ValueError):
        saved = None
    if not saved and isinstance(config.get("dashboard.widgets"), list):
        saved = {"kpis": DEFAULT_LAYOUT["kpis"], "widgets": config.get("dashboard.widgets")}
    lay = saved or DEFAULT_LAYOUT
    return {"kpis": [k for k in lay.get("kpis", []) if k in KPIS] or DEFAULT_LAYOUT["kpis"],
            "widgets": [w for w in lay.get("widgets", []) if w in WIDGETS],
            "custom": bool(saved)}


def save_layout(lay):
    clean = {"kpis": [k for k in (lay.get("kpis") or []) if k in KPIS][:16],
             "widgets": [w for w in dict.fromkeys(lay.get("widgets") or []) if w in WIDGETS][:24]}
    with _rw() as con:
        con.execute("insert into ui_settings(k, v, updated) values('layout', ?, datetime('now')) "
                    "on conflict(k) do update set v=excluded.v, updated=excluded.updated", (json.dumps(clean),))
    return clean


def reset_layout():
    with _rw() as con:
        con.execute("delete from ui_settings where k='layout'")


# ── focused views (REST API + MCP) ───────────────────────────────────────────
def _clamp(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def summary():
    """Posture at a glance: mode, headline numbers, collector health, what needs a decision."""
    p = payload()
    v = p.get("vuln") or {}
    k = dict(p["kpi"], vuln_kev=(v.get("totals") or {}).get("kev") or 0,
             vuln_fixable=(v.get("totals") or {}).get("fixable") or 0,
             ids_24h=p["netsec"]["ids_24h"], intel_24h=p["netsec"]["intel_24h"],
             integrity_open=sum(r.get("open", 0) for r in p["endpoints"]["integrity"]))
    try:
        from . import notify  # noqa: PLC0415
        k["approvals"] = len(notify.pending())
    except Exception:  # noqa: BLE001
        k["approvals"] = 0
    return {"estate": config.get("estate.name"), "mode": p["mode"], "kpi": k, "health": p["health"]}


def detections(hours=24, limit=100, min_score=0, ip="", include_self=False):
    """Our own addresses are left out unless asked for by IP or include_self — they are monitoring, not attacks."""
    hours, limit, min_score = _clamp(hours, 1, 24 * 90, 24), _clamp(limit, 1, 1000, 100), _clamp(min_score, 0, 1000, 0)
    sql = ("select ts, source, ip, kind, detail, score from events where ts > datetime('now', ?) and score >= ?"
           + (" and ip = ?" if ip else "") + " order by id desc limit ?")
    args = [f"-{hours} hours", min_score] + ([ip] if ip else [])
    if include_self or ip:
        return {"hours": hours, "rows": tag(q(sql, args + [limit]), redlist()["watch"]), "self_hidden": 0}
    rows, hidden = _not_self(sql + " offset ?", args, limit, redlist()["watch"])
    return {"hours": hours, "rows": rows, "self_hidden": hidden}


def top_ips(days=30, limit=25):
    days, limit = _clamp(days, 1, 365, 30), _clamp(limit, 1, 200, 25)
    return {"days": days, "rows": [r for r in tag(q(
        "select ip, sum(score) score, count(*) n, group_concat(distinct kind) kinds, max(ts) last from events "
        "where ip!='' and ts > datetime('now', ?) group by ip order by score desc limit ?",
        (f"-{days} days", limit + 50)), redlist()["watch"]) if not r["self"]][:limit]}


def bans():
    p = payload()
    return {"mode": p["mode"], "proposed_or_active": p["bans"], "edge_blocklist": p["edge_bans"]}


def vulns(target=""):
    if target:
        return {"target": target, "rows": q(
            f"select vid,pkg,installed,fixed,severity,title,kev,status,image from vulns where target=? "
            f"order by kev desc, (fixed!='') desc, {SEV} desc limit 3000", (target[:64],))}
    v = vuln_payload()
    if not v:
        return {"enabled": False}
    return {"enabled": True, "totals": v["totals"], "targets": v["targets"], "top": v["top"][:100],
            "images": v["images"], "patch_jobs": v["jobs"]}


def cve(vid):
    """One CVE across the estate: what it is, where it is, what fixes it — the drawer behind every CVE id."""
    vid = (vid or "").strip()[:40]
    if not vid or not has("vulns"):
        return {"vid": vid, "rows": []}
    cols = {r["name"] for r in q("pragma table_info(vulns)")}
    extra = "".join(f", v.{c}" for c in ("descr", "url") if c in cols)   # absent until vulnscan migrates
    rows = q(f"select v.target, coalesce(t.name, v.target) name, v.pkg, v.installed, v.fixed, v.severity, v.title, "
             f"v.kev, v.status, v.image{extra} "
             f"from vulns v left join vuln_targets t on t.target=v.target where v.vid=? order by v.target", (vid,))
    first = rows[0] if rows else {}
    return {"vid": vid, "severity": first.get("severity"), "title": first.get("title"), "kev": any(r["kev"] for r in rows),
            "descr": next((r.get("descr") for r in rows if r.get("descr")), ""),
            "url": next((r.get("url") for r in rows if r.get("url")), ""), "rows": rows,
            "links": {"NVD": f"https://nvd.nist.gov/vuln/detail/{vid}", "OSV": f"https://osv.dev/vulnerability/{vid}",
                      "CISA KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + vid}}


def attack_surface():
    surf = q("select ts, data from surface_snap order by id desc limit 1")
    s = json.loads(surf[0]["data"]) if surf else {}
    return {"snapshot": surf[0]["ts"] if surf else None, "findings": s.get("findings", []),
            "public_names": s.get("hosts", []), "waf_rules": s.get("waf", []), "zone_settings": s.get("settings", {}),
            "lan_ports": payload()["net_ports"]}


def network():
    return {"hosts": q("select mac,ip,hostname,vendor,first_seen,last_seen,approved from net_hosts"),
            "alerts": q("select ts,kind,mac,ip,detail from net_alerts order by id desc limit 200"),
            "last_sweep": q("select ts last_run, hosts from net_runs order by id desc limit 1")}


def ids():
    return netsec_payload()


def integrity():
    return endpoints_payload()


def health():
    return {"collectors": payload()["health"],
            "suppressed": q("select ts,kind,detail,reason from alert_suppressed order by id desc limit 50")}


def lookup_ip(ip):
    """Everything warden knows about one address."""
    ip = (ip or "").strip()[:64]
    nets, red = self_nets(), redlist()
    cc = GEO.cc(ip)
    return {"ip": ip, "cc": cc, "red_list": cc in red["watch"], "self": is_self(ip, nets),
            "score_30d": (q("select sum(score) s from events where ip=? and ts > datetime('now','-30 days')", (ip,))
                          or [{"s": 0}])[0]["s"] or 0,
            "events": q("select ts,source,kind,detail,score from events where ip=? order by id desc limit 50", (ip,)),
            "edge": q("select ts,action,host,path,rule from edge_events where ip=? order by id desc limit 50", (ip,))
            if has("edge_events") else [],
            "bans": q("select ts,score,reasons,state from bans where ip=? order by id desc limit 10", (ip,)),
            "lan_host": q("select mac,hostname,vendor,first_seen,last_seen from net_hosts where ip=?", (ip,))}
