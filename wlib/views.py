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


def _hosthealth():
    """Beszel's verdict per host (optional integration, None when off). Never breaks the page."""
    try:
        from . import hosthealth  # noqa: PLC0415
        return hosthealth.fetch()
    except Exception as e:  # noqa: BLE001
        return {"enabled": True, "error": f"{type(e).__name__}: {str(e)[:160]}", "hosts": [], "summary": None}


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
        "hosthealth": _hosthealth(),
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
        "devices": devices_list(),
        "device_changes": device_changes(50),
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
        "topology": topology(),
        "incidents": incidents(),
        "agents": agents_payload(),
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
    out.update(heartbeat_payload())
    return out


# Linux capability names by bit (used only to turn a CapEff hex mask into plain English; no dependency).
CAP_NAMES = ["chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
             "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
             "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
             "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
             "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
             "checkpoint_restore"]
# Capabilities worth flagging as near-root, and groups that hand out root-equivalent access.
CAP_HOT = {"sys_admin", "sys_ptrace", "sys_module", "dac_override", "dac_read_search", "net_admin", "net_raw",
           "sys_rawio", "setuid", "setgid", "bpf"}
GROUP_HOT = {"sudo", "wheel", "root", "docker", "adm", "lxd", "disk", "shadow"}


def _caps(hexmask):
    """A CapEff hex mask -> (list of capability names, is_full_root)."""
    try:
        m = int(hexmask, 16)
    except (TypeError, ValueError):
        return [], False
    full = (m & 0x1FFFFFFFFFF) == 0x1FFFFFFFFFF                 # all 41 defined bits set == effectively root
    names = [CAP_NAMES[i] for i in range(len(CAP_NAMES)) if m & (1 << i)]
    return names, full


def _grp_names(gid, groups):
    """(primary group name, [supplementary group names]) from a gid and a space-separated gid string, best-effort."""
    import grp
    def nm(g):
        try:
            return grp.getgrgid(int(g)).gr_name
        except (KeyError, ValueError, OverflowError, TypeError):
            return str(g)
    prim = nm(gid) if gid not in (None, -1, "") else ""
    sup = [nm(g) for g in str(groups or "").split() if g]
    return prim, sup


def _can_read(uid, gid, gids, stat):
    """Could a process with this uid/gid/supplementary-gids read a file with this 'owner:group:mode' stat? Best-effort."""
    if uid == 0:
        return True
    try:
        ou, og, mode = stat.split(":")
        ou, og = int(ou), int(og)
        perm = int(mode[-3:], 8) if len(mode) >= 3 else int(mode, 8)
    except (ValueError, AttributeError):
        return None                                            # unknown — don't claim either way
    owns = {int(gid)} | {int(g) for g in str(gids or "").split() if g.isdigit()}
    if uid == ou:
        return bool(perm & 0o400)
    if og in owns:
        return bool(perm & 0o040)
    return bool(perm & 0o004)


def agents_payload():
    """AI agent egress: one row per agent with its destinations, any known-bad hits, what each agent can access on the
    box it runs on, the review/coverage detail, and a known-bad-aware destination history (with best-effort bytes)."""
    if not has("agent_conns"):
        return {"agents": [], "conns": [], "alerts": [], "findings": [], "runs": [], "perms": [], "dests": []}
    has_bytes = "bytes_recv" in {r["name"] for r in q("pragma table_info(agent_conns)")}
    bcol = "bytes_recv" if has_bytes else "0 bytes_recv"
    bagg = "bytes_recv" if has_bytes else "0"   # aggregate form: max(0) is valid, max(0 bytes_recv) is not
    bad_ips = {r["dest_ip"] for r in q("select distinct dest_ip from agent_alerts")} if has("agent_alerts") else set()
    bad_dests = {r["dest"] for r in q("select distinct dest from agent_alerts")} if has("agent_alerts") else set()

    conns = q(f"select agent,host,dest,dest_ip,port,domain,first_seen,last_seen,hits,container,{bcol} from agent_conns "
              "order by agent, hits desc")
    for c in conns:
        c["bad"] = c["dest_ip"] in bad_ips or c["dest"] in bad_dests
        c["cc"] = GEO.cc(c["dest_ip"] or "")

    # Destination history across ALL agents: one row per destination, known-bad first, with totals and who reached it.
    dests = q(f"""select dest, dest_ip, max(domain) domain, group_concat(distinct agent) agents, count(distinct agent) n_agents,
                  min(first_seen) first_seen, max(last_seen) last_seen, sum(hits) hits, max({bagg}) bytes_recv
                  from agent_conns group by dest order by hits desc""")
    for d in dests:
        d["bad"] = d["dest_ip"] in bad_ips or d["dest"] in bad_dests
    dests.sort(key=lambda d: (not d["bad"], -(d["hits"] or 0)))

    perms = []
    if has("agent_perms"):
        files = q("select host,path,stat from agent_files") if has("agent_files") else []
        fbyhost = {}
        for f in files:
            fbyhost.setdefault(f["host"], []).append(f)
        for p in q("select agent,host,ts,user,uid,gid,groups,caps,sudo,root from agent_perms order by agent,host"):
            caps, full = _caps(p["caps"])
            prim, sup = _grp_names(p["gid"], p["groups"])
            hot_grp = sorted(GROUP_HOT.intersection([prim] + sup))
            reads = []
            for f in fbyhost.get(p["host"], []):
                r = _can_read(p["uid"], p["gid"], p["groups"], f["stat"])
                if r:
                    reads.append(f["path"])
            has_sudo = bool((p["sudo"] or "").strip()) and "none or unknown" not in (p["sudo"] or "")
            perms.append({**p, "cap_names": caps, "cap_full": full,
                          "cap_hot": sorted(CAP_HOT.intersection(caps)) or (["(all)"] if full else []),
                          "group": prim, "groups_list": sup, "hot_groups": hot_grp, "has_sudo": has_sudo,
                          "can_read": reads,
                          "privileged": bool(p["root"]) or full or bool(hot_grp) or has_sudo})

    return {
        "agents": q("""select a.agent, max(a.host) host, count(*) dests, sum(a.hits) conns, max(a.last_seen) last_seen,
                       (select count(*) from agent_alerts al where al.agent=a.agent) alerts
                       from agent_conns a group by a.agent order by alerts desc, conns desc"""),
        "conns": conns,
        "dests": dests,
        "perms": perms,
        "alerts": q("select ts,agent,host,dest,dest_ip,kind,feed,detail from agent_alerts order by id desc limit 100"),
        "findings": q("select ts,agent,host,dest,score,decision,reasons,explain,verdict from agent_findings "
                      "order by (verdict is null) desc, id desc limit 200"),
        "runs": q("select host,ts,status,note,seen,attributed from agent_runs order by host"),
    }


def heartbeat_payload():
    """heartbeat.py: is each box up, who last signed in (not counting warden's own key), 24-h counts, recent sign-ins."""
    if not has("hb"):
        return {"heartbeat": [], "logins": [], "hb_events": []}
    labels = {str(k): str(v) for k, v in (config.get("logins.known_keys") or {}).items()}
    login = has("logins")
    rows = []
    for r in q("select * from hb order by kind != 'node', node, target"):
        last = (q("select ts,user,src,method,key_fp,new from logins where target=? and ok=1 and self=0 "
                  "order by ts desc limit 1", (r["target"],)) or
                q("select last_ts ts,user,src,'' method,key_fp,0 new from login_pairs where target=? and ok=1 and self=0 "
                  "order by last_ts desc limit 1", (r["target"],))) if login else []
        n = q("select sum(ok=1 and self=0) h, sum(ok=1 and self=1) s, sum(ok=0) f from logins where target=? "
              "and ts > datetime('now','-24 hours')", (r["target"],))[0] if login else {}
        if last:
            last[0]["key_label"] = labels.get(last[0]["key_fp"] or "", "")
        rows.append(dict(r, last_login=last[0] if last else None, logins_24h=n.get("h") or 0,
                         self_24h=n.get("s") or 0, failed_24h=n.get("f") or 0))
    recent = q("select l.ts,l.target,coalesce(h.name,l.target) name,l.user,l.src,l.method,l.key_fp,l.ok,l.new "
               "from logins l left join hb h on h.target=l.target where l.self=0 and l.ts > datetime('now','-7 days') "
               "order by l.ts desc limit 300") if login else []
    for r in recent:
        r["key_label"] = labels.get(r["key_fp"] or "", "")
    return {"heartbeat": rows, "logins": recent,
            "hb_events": q("select ts,target,event,detail from hb_events order by id desc limit 50")}


def incidents(limit=60):
    """incidents.py (SHADOW): joined-up incidents, the model's would-be action (never acted on) and what the owner did."""
    if not has("incidents"):
        return {"mode": "not run yet", "rows": []}
    mode = str((config.get("incidents") or {}).get("mode") or "shadow")
    rows = q("select i.id, i.entity, i.kind, i.opened, i.last_seen, i.n_facts, i.weight, i.owner_label, i.owner_source, "
             "d.status, d.action, d.confidence, d.why, d.cited, d.reason, d.model, d.ts decided "
             "from incidents i left join incident_decisions d on d.id = (select max(id) from incident_decisions "
             "where incident_id = i.id) order by (d.id is not null) desc, i.last_seen desc limit ?", (limit,))
    for r in rows:
        r["facts"] = q("select fact_id, ts, source, summary from incident_facts where incident_id=? "
                       "order by weight desc, ts desc limit 12", (r["id"],))
    return {"mode": mode, "rows": rows}


def topology():
    """What the Network tab's diagram is drawn from: the way in from the internet, the router, each subnet with the
    servers warden manages (containers under their node, heartbeat state) and every other device counted by kind.
    Built from data warden already has — nothing here is hand-drawn, so it stays true as the network changes."""
    import ipaddress
    nets = []
    for c in (config.get("estate.lan") or []):
        try:
            nets.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            pass
    labels = {str(k): str(v) for k, v in (config.get("network.subnets") or {}).items()}

    def subnet(ip):
        try:
            a = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return None
        if a.is_loopback or a.is_link_local or not a.is_private:
            return None
        for n in nets:
            if a in n:
                return str(n)
        return str(ipaddress.ip_network(f"{a}/24", strict=False))

    addr = lambda ssh: (ssh or "").split("@")[-1] or None  # noqa: E731
    src = config.get("sources") or {}
    gw = config.get("netwatch.gateway") or addr(config.get("router.ssh"))
    line = q("select ts,state,gw_ms,gw_loss,wan_ms,wan_loss,rx_mbps,tx_mbps from net_health order by ts desc limit 1") \
        if has("net_health") else []
    hb = {r["target"]: r for r in q("select target,name,kind,node,state,uptime_s,last_ok from hb")} if has("hb") else {}
    servers = []
    from . import hosts as _hosts
    for h in _hosts.declared():
        kind, ip = h.get("kind", "linux"), addr(h.get("ssh")) or ""
        if kind == "local":
            continue
        tid = f"node:{ip}" if kind == "proxmox" else f"host:{ip}" if kind == "linux" else None
        b = hb.get(tid, {}) if tid else {}
        cts = sorted(({"target": t, "name": r["name"], "state": r["state"], "uptime_s": r["uptime_s"]}
                      for t, r in hb.items() if r["kind"] == "ct" and r["node"] == ip),
                     key=lambda c: int(c["target"].split(":")[1]))
        servers.append({"name": h.get("name") or ip, "kind": kind, "ip": ip, "target": tid, "state": b.get("state"),
                        "uptime_s": b.get("uptime_s"), "subnet": subnet(ip), "cts": cts, "docker": bool(h.get("docker"))})
    if not servers:     # no hosts in warden.yml (demo data, or config moved): draw what the heartbeat has seen
        for t, r in sorted(hb.items()):
            if r["kind"] not in ("node", "host"):
                continue
            ip = t.split(":", 1)[1]
            cts = sorted(({"target": c, "name": x["name"], "state": x["state"], "uptime_s": x["uptime_s"]}
                          for c, x in hb.items() if x["kind"] == "ct" and x["node"] == ip),
                         key=lambda c: int(c["target"].split(":")[1]))
            servers.append({"name": r["name"], "kind": "proxmox" if r["kind"] == "node" else "linux", "ip": ip, "target": t,
                            "state": r["state"], "uptime_s": r["uptime_s"], "subnet": subnet(ip), "cts": cts, "docker": False})
    groups = {}
    for d in devices_list():
        ip = (d.get("ips") or "").split(",")[-1]
        sn = subnet(ip)
        if not sn:
            continue
        g = groups.setdefault(sn, {"cidr": sn, "label": labels.get(sn, ""), "devices": 0, "kinds": {}})
        g["devices"] += 1
        k = d.get("kind") or "unknown"
        g["kinds"][k] = g["kinds"].get(k, 0) + 1
    for n in nets:
        groups.setdefault(str(n), {"cidr": str(n), "label": labels.get(str(n), ""), "devices": 0, "kinds": {}})
    for s in servers:
        if s["subnet"] and s["subnet"] not in groups:
            groups[s["subnet"]] = {"cidr": s["subnet"], "label": labels.get(s["subnet"], ""), "devices": 0, "kinds": {}}
    order = sorted(groups.values(), key=lambda g: (-sum(1 for s in servers if s["subnet"] == g["cidr"]), -g["devices"]))
    cf = config.get("cloudflare") or {}
    return {
        "gateway": {"ip": gw, "subnet": subnet(gw) if gw else None},
        "line": line[0] if line else None,
        "edge": {"cloudflare": bool(cf.get("zone_id")), "domain": config.get("estate.domain") or "",
                 "tunnel": addr((src.get("cloudflared") or {}).get("ssh")), "proxy": addr((src.get("npm") or {}).get("ssh")),
                 "sso": bool(src.get("authelia")) or bool(cf.get("sso_portal"))},
        "servers": servers,
        "subnets": [dict(g, kinds=sorted(({"k": k, "n": n} for k, n in g["kinds"].items()), key=lambda x: -x["n"]))
                    for g in order],
    }


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
        # what matters: known-exploited, then likely-to-be-exploited (EPSS ≥ 10% with a fix), then severity
        "top": q(f"select vid, max({SEV}) sev, max(kev) kev, count(distinct target) n_targets, "
                 "group_concat(distinct target) targets, group_concat(distinct pkg) pkgs, max(fixed) fixed, "
                 f"max(title) title{', max(epss) epss, max(epss_pct) epss_pct, max(exposed) exposed' if _epss() else ''} "
                 "from vulns where fixed!='' or kev=1 group by vid "
                 f"order by kev desc, {'(max(epss)>=0.1) desc, (max(exposed) is not null) desc, ' if _epss() else ''}"
                 "sev desc, n_targets desc limit 400"),
        "exposure": q("select host, upstream, target, image, container, sso, via from exposure order by sso, host")
        if has("exposure") else [],
        "brief": (q("select ts, model, status, text, reason from vuln_brief order by id desc limit 1") or [None])[0]
        if has("vuln_brief") else None,
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


FIELDS = {"ip", "cc", "kind", "src", "host", "type", "date"}


def _field_match(r, field, val, hay):
    """Does row r match field:val (negation handled by the caller)?"""
    if field == "ip":
        return (r.get("ip") or "").startswith(val)
    if field == "cc":
        return (r.get("cc") or "").lower() == val
    if field == "kind":
        return val in (r.get("kind") or "").lower()
    if field == "src":
        return val in (r.get("source") or "").lower()
    if field == "type":
        return val == r["type"]
    if field == "date":
        return (r.get("ts") or "").lower().startswith(val)
    if field == "host":
        return val in hay
    return True


def search(text):
    """Unified search. Every row: ts, type, source, ip, cc, kind, detail, score. Supports field:value terms
    (ip/cc/kind/src/type/host/date), free text, and negation with a leading '-' (e.g. -kind:challenge)."""
    preds, free = [], []                                       # preds: (neg, field, value); free: (neg, word)
    for t in (text or "").split():
        neg = t.startswith("-") and len(t) > 1
        body = t[1:] if neg else t
        k, sep, v = body.partition(":")
        if sep and k.lower() in FIELDS and v:
            preds.append((neg, k.lower(), v.lower()))
        else:
            free.append((neg, body.lower()))
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
        if any(_field_match(r, f, v, hay) == neg for neg, f, v in preds):
            continue                                           # a positive term must match; a negated term must not
        if all((w in hay) != neg for neg, w in free):
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
    "hosthealth": {"title": "Host health · Beszel", "type": "hosthealth", "size": 2},
    "map":       {"title": "Where traffic comes from · 30 days", "type": "map", "size": 4},
    "numbers":   {"title": "Numbers (the KPI row)", "type": "kpis", "size": 4},
}


def auto_widgets():
    """New widgets that turn up by themselves once (a saved layout would never show them otherwise); an integration's
    widget only while it is enabled. Removing one in Customise sticks (layout "seen")."""
    return ["map"] + (["hosthealth"] if (config.get("beszel") or {}).get("enabled") else [])
KPIS = ["events_24h", "ips_7d", "edge_24h", "red_hits_7d", "findings_open", "bans", "hosts", "vuln_kev", "vuln_fixable",
        "ids_24h", "integrity_open", "approvals"]
DEFAULT_LAYOUT = {"kpis": ["events_24h", "ips_7d", "edge_24h", "red_hits_7d", "findings_open", "bans", "hosts"],
                  "widgets": ["map", "kind", "source", "country", "edge", "tl30", "findings", "top"]}


def _rw():
    con = sqlite3.connect(config.DB, timeout=30)
    con.execute("create table if not exists ui_settings(k text primary key, v text, updated text)")
    return con


def _saved_layout():
    try:
        with _rw() as con:
            r = con.execute("select v from ui_settings where k='layout'").fetchone()
        return json.loads(r[0]) if r else None
    except (sqlite3.Error, ValueError):
        return None


def layout():
    """Saved layout, else warden.yml `dashboard.widgets`, else the default. Unknown ids are dropped,
    so a widget removed in a later version cannot break the page. An integration's widget (auto_widgets) appears
    by itself the first time it is enabled, and is hidden again when it is turned off."""
    saved = _saved_layout()
    if not saved and isinstance(config.get("dashboard.widgets"), list):
        saved = {"kpis": DEFAULT_LAYOUT["kpis"], "widgets": config.get("dashboard.widgets")}
    lay = saved or DEFAULT_LAYOUT
    auto = auto_widgets()
    widgets = [w for w in lay.get("widgets", []) if w in WIDGETS and (w not in ("hosthealth",) or w in auto)]
    seen = set(lay.get("seen") or [])
    for w in auto:
        if w not in widgets and w not in seen:
            widgets.insert(0, w)
    return {"kpis": [k for k in lay.get("kpis", []) if k in KPIS] or DEFAULT_LAYOUT["kpis"],
            "widgets": widgets, "custom": bool(saved)}


def save_layout(lay):
    clean = {"kpis": [k for k in (lay.get("kpis") or []) if k in KPIS][:16],
             "widgets": [w for w in dict.fromkeys(lay.get("widgets") or []) if w in WIDGETS][:24]}
    # an auto widget on screen while this layout was edited has been "seen": if it was left out, it stays out
    clean["seen"] = sorted(set((_saved_layout() or {}).get("seen") or []) | set(auto_widgets()))
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
    return {"estate": config.get("estate.name"), "mode": p["mode"], "kpi": k, "health": p["health"],
            "host_health": (p.get("hosthealth") or {}).get("summary")}


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


def _epss():
    # epss and exposed arrived together (2026-10-10)
    return has("vulns") and {"epss", "exposed"} <= {r["name"] for r in q("pragma table_info(vulns)")}


def vulns(target=""):
    if target:
        e = ",epss,epss_pct,exposed" if _epss() else ""
        return {"target": target, "rows": q(
            f"select vid,pkg,installed,fixed,severity,title,kev,status,image{e} from vulns where target=? "
            f"order by kev desc, (fixed!='') desc, {'coalesce(epss,0)>=0.1 desc, ' if e else ''}{SEV} desc limit 3000",
            (target[:64],))}
    v = vuln_payload()
    if not v:
        return {"enabled": False}
    return {"enabled": True, "totals": v["totals"], "targets": v["targets"], "top": v["top"][:100],
            "images": v["images"], "patch_jobs": v["jobs"], "brief": v.get("brief")}


def cve(vid):
    """One CVE across the estate: what it is, where it is, what fixes it — the drawer behind every CVE id."""
    vid = (vid or "").strip()[:40]
    if not vid or not has("vulns"):
        return {"vid": vid, "rows": []}
    cols = {r["name"] for r in q("pragma table_info(vulns)")}
    extra = "".join(f", v.{c}" for c in ("descr", "url", "epss", "epss_pct", "exposed") if c in cols)  # until migrated
    rows = q(f"select v.target, coalesce(t.name, v.target) name, v.pkg, v.installed, v.fixed, v.severity, v.title, "
             f"v.kev, v.status, v.image{extra} "
             f"from vulns v left join vuln_targets t on t.target=v.target where v.vid=? order by v.target", (vid,))
    first = rows[0] if rows else {}
    return {"vid": vid, "severity": first.get("severity"), "title": first.get("title"), "kev": any(r["kev"] for r in rows),
            "descr": next((r.get("descr") for r in rows if r.get("descr")), ""),
            "url": next((r.get("url") for r in rows if r.get("url")), ""), "rows": rows,
            "epss": next((r.get("epss") for r in rows if r.get("epss") is not None), None),
            "epss_pct": next((r.get("epss_pct") for r in rows if r.get("epss_pct") is not None), None),
            "links": {"NVD": f"https://nvd.nist.gov/vuln/detail/{vid}", "OSV": f"https://osv.dev/vulnerability/{vid}",
                      "CISA KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + vid}}


def attack_surface():
    surf = q("select ts, data from surface_snap order by id desc limit 1")
    s = json.loads(surf[0]["data"]) if surf else {}
    return {"snapshot": surf[0]["ts"] if surf else None, "findings": s.get("findings", []),
            "public_names": s.get("hosts", []), "waf_rules": s.get("waf", []), "zone_settings": s.get("settings", {}),
            "lan_ports": payload()["net_ports"]}


def devices_list():
    """One row per real device (devices.py groups a phone's rotating private addresses into one)."""
    if not has("devices"):
        return []
    return q("select identity, max(last_seen) last_seen, name, kind, kind_why, room, fixed, maker, model, sources, "
             "group_concat(distinct ip) ips, count(*) addresses, min(first_seen) first_seen from devices "
             "group by identity order by kind, name")


def device(key):
    """One device: its inventory row(s) and what it normally talks to. key = identity, IP, MAC or a name fragment."""
    if not has("devices"):
        return {"error": "devices.py has not run yet"}
    key = (key or "").strip()[:80]
    rows = q("select * from devices where identity=? or ip=? or mac=? order by last_seen desc", (key, key, key.lower())) \
        or q("select * from devices where name like ? order by last_seen desc limit 5", (f"%{key}%",))
    if not rows:
        return {"error": f"no device matches {key!r}"}
    import sqlite3 as _s
    from . import behaviour
    con = _s.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=10)
    try:
        prof = behaviour.profile(con, rows[0]["identity"]) if has("dev_dns") else {"domains": [], "learning": True}
    finally:
        con.close()
    return {"device": {k: rows[0][k] for k in ("name", "kind", "kind_why", "room", "maker", "model", "ip", "identity",
                                                "first_seen", "last_seen", "sources")},
            "addresses": len(rows), "behaviour": prof}


def device_changes(limit=100):
    """devicewatch.py decisions: a fixed-function device doing something new, scored, with the owner's verdict."""
    if not has("dev_findings"):
        return []
    return q("select f.ts, f.domain, f.score, f.decision, f.reasons, f.explain, f.verdict, f.decided_at, "
             "coalesce(d.name, f.identity) device, d.kind from dev_findings f left join "
             "(select identity, name, kind, max(last_seen) from devices group by identity) d on d.identity=f.identity "
             "order by f.ts desc limit ?", (limit,))


def network():
    return {"devices": devices_list(), "device_changes": device_changes(),
            "hosts": q("select mac,ip,hostname,vendor,first_seen,last_seen,approved from net_hosts"),
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
