#!/usr/bin/env python3
"""Fill a database with believable DEMO data, for screenshots and for trying the console.

  WARDEN_DATA=/tmp/warden-demo python3 tools/demo.py
  WARDEN_CONF=tools/demo.yml WARDEN_DATA=/tmp/warden-demo python3 tools/demo.py    # + hosts, an IoT VLAN, Cloudflare: the full map

Every address is from the documentation ranges (RFC 5737: 192.0.2/24, 198.51.100/24,
203.0.113/24) or a private range; every hostname ends in example.com. Refuses to
touch a database that already has events, so it can never mix into real data.
"""
import json
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wlib import config  # noqa: E402

random.seed(7)
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def ts(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


def main():
    config.DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DB)
    con.executescript((Path(__file__).with_name("schema.sql")).read_text().replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
                      .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS "))
    if con.execute("select count(*) from events").fetchone()[0]:
        sys.exit("refusing: this database already has events (demo data only goes into an empty one)")

    attackers = [("203.0.113.%d" % i) for i in (9, 23, 41, 77, 150)] + ["198.51.100.%d" % i for i in (4, 66, 201)]
    kinds = [("sensitive-file", "/.env", 8), ("sensitive-file", "/.git/config", 8), ("traversal", "/../../etc/passwd", 8),
             ("sqli", "/item?id=1%27%20or%201=1", 8), ("scanner-ua", "zgrab/0.x", 5), ("wp-probe", "/wp-login.php", 4),
             ("auth-failure", "bad password for admin", 3), ("4xx", "404 /favicon2.ico", 1)]
    srcs = ["npm", "authelia", "cloudflared"]
    for day in range(30):
        for _ in range(random.randint(4, 30) + (25 if day in (3, 11) else 0)):
            ip = random.choice(attackers + ["192.0.2.%d" % random.randint(2, 250)])
            k, d, s = random.choice(kinds)
            src = "authelia" if k == "auth-failure" else random.choice(srcs[:1] * 4 + srcs[2:])
            con.execute("insert into events(ts,source,ip,kind,detail,score) values(?,?,?,?,?,?)",
                        (ts(days=day, minutes=random.randint(0, 1439)), src, ip, k, d, s))
    for src, lines, parsed in (("npm", 18234, 41), ("authelia", 922, 6), ("cloudflared", 3110, 2), ("cf-edge", 410, 12)):
        con.execute("insert into runs(ts,source,lines,parsed,note) values(?,?,?,?,?)", (ts(minutes=3), src, lines, parsed, ""))
    con.execute("insert into bans(ts,ip,score,reasons,state,note) values(?,?,?,?,?,?)",
                (ts(hours=5), "203.0.113.41", 31, "sensitive-file×2, traversal, sqli", "proposed", "detect-only"))
    ccs = ["US", "NL", "DE", "CN", "RU", "SG", "GB", "FR"]
    for i in range(160):
        con.execute("insert into edge_events(ts,ray,ip,cc,action,source,host,path,ua,rule) values(?,?,?,?,?,?,?,?,?,?)",
                    (ts(hours=random.randint(0, 47), minutes=random.randint(0, 59)), f"demo{i}",
                     random.choice(attackers), random.choice(ccs),
                     random.choice(["block", "managed_challenge", "block", "link_maze_injected"]),
                     "firewallCustom", random.choice(["photos.example.com", "auth.example.com"]),
                     random.choice(["/.env", "/wp-admin/", "/.git/HEAD", "/cgi-bin/luci"]), "Mozilla/5.0 (demo)",
                     random.choice(["block scanners", "block .env/.git", "challenge bad ASNs"])))
    con.execute("insert into edge_bans(target,reason,score,status,created,expires) values(?,?,?,?,?,?)",
                ("203.0.113.0/24", "4 addresses, 212 events in 7 d", 212, "pending", ts(hours=2), None))
    surface = {"findings": [
        {"sev": "high", "host": "old.example.com", "issue": "public DNS name resolves to a private address"},
        {"sev": "medium", "host": "photos.example.com", "issue": "not behind SSO (exempt: mobile app cannot follow a redirect)", "accepted": True},
        {"sev": "medium", "host": "example.com", "issue": "minimum TLS version is 1.0"}],
        "hosts": [{"name": "auth.example.com", "kind": "sso-portal"}, {"name": "photos.example.com", "kind": "app"},
                  {"name": "vpn.example.com", "kind": "vpn"}],
        "waf": [{"action": "block", "desc": "block scanners", "expr": '(http.user_agent contains "zgrab")', "enabled": True},
                {"action": "block", "desc": "block .env/.git", "expr": '(http.request.uri.path contains "/.env")', "enabled": True}],
        "settings": {"min_tls_version": "1.0", "ssl": "strict", "always_use_https": "on"}, "pages": []}
    con.execute("insert into surface_snap(ts,data) values(?,?)", (ts(minutes=20), json.dumps(surface)))
    lan = [("aa:00:00:00:00:%02x" % i, "192.168.1.%d" % ip, name, vendor) for i, (ip, name, vendor) in enumerate([
        (1, "router", "OpenWrt"), (2, "pve1", "Intel"), (5, "nas", "Realtek"), (7, "llm", "ASUSTek"),
        (21, "tv", "Samsung"), (31, "bulb-kitchen", "Espressif"), (32, "bulb-hall", "Espressif"), (40, "phone", "Apple")])]
    for mac, ip, name, vendor in lan:
        con.execute("insert into net_hosts(mac,ip,hostname,vendor,first_seen,last_seen,approved) values(?,?,?,?,?,?,1)",
                    (mac, ip, name, vendor, ts(days=40), ts(minutes=4)))
    for mac, port, svc in (("aa:00:00:00:00:02", 8006, "pve"), ("aa:00:00:00:00:02", 22, "ssh"),
                           ("aa:00:00:00:00:03", 445, "microsoft-ds"), ("aa:00:00:00:00:03", 2049, "nfs")):
        con.execute("insert into net_ports(mac,port,proto,service,first_seen,last_seen) values(?,?,?,?,?,?)",
                    (mac, port, "tcp", svc, ts(days=20), ts(hours=6)))
    for k, d in (("NEW_DEVICE", "unknown Espressif device"), ("IP_CONFLICT", "two MACs answered on 192.168.1.32"),
                 ("NEW_PORT", "nas opened 2049/nfs")):
        con.execute("insert into net_alerts(ts,kind,mac,ip,detail) values(?,?,?,?,?)", (ts(days=random.randint(0, 20)), k,
                    "aa:00:00:00:00:06", "192.168.1.32", d))
    con.execute("insert into net_runs(ts,network,hosts) values(?,?,?)", (ts(minutes=4), "192.168.1.0/24", len(lan)))
    targets = [("node:192.168.1.2", "node", "pve1", 1, 0, 3, 0), ("ct:100", "ct", "proxy", 1, 1, 9, 1),
               ("ct:104", "ct", "docker", 1, 0, 2, 0), ("img:nas", "images", "nas Docker images", 0, 2, 41, 3)]
    for tgt, kind, name, patchable, crit, fixable, kev in targets:
        con.execute("insert into vuln_targets(target,kind,name,os,last_scan,status,patchable,n_total,n_fixable,n_crit_fix,"
                    "n_high_fix,n_kev,upgradable,reboot_required) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tgt, kind, name, "debian 12", ts(hours=7), "ok", patchable, fixable * 30, fixable, crit, fixable // 3,
                     kev, fixable, 0))
        for j in range(fixable):
            sev = "CRITICAL" if j < crit else random.choice(["HIGH", "MEDIUM", "LOW"])
            con.execute("insert or ignore into vulns(target,vid,pkg,installed,fixed,severity,title,kev,status,image) "
                        "values(?,?,?,?,?,?,?,?,?,?)", (tgt, f"CVE-2026-{1000 + j * 7 + len(tgt)}",
                        random.choice(["openssl", "libxml2", "curl", "glibc", "nginx"]), "1.0", "1.1", sev,
                        "demo finding", 1 if j < kev else 0, "fixed", "demo/app:latest" if kind == "images" else ""))
    for t, name, idx in (("ct:100", "proxy", 71), ("node:192.168.1.2", "pve1", 64)):
        con.execute("insert into harden(target,name,ts,idx,prev_idx,tests,warnings,suggestions,status) values(?,?,?,?,?,?,?,?,?)",
                    (t, name, ts(days=2), idx, idx - 2, 260, json.dumps([]), json.dumps([{"id": "SSH-7408", "text": "harden sshd"}]), "ok"))
        con.execute("insert into integ_runs(target,ts,facts,status) values(?,?,?,?)", (t, ts(minutes=20), 412, "ok"))
    con.execute("insert into integ_find(ts,target,kind,item,old,new,change,status) values(?,?,?,?,?,?,?,?)",
                (ts(hours=3), "ct:100", "file", "/etc/ssh/sshd_config", "a1b2", "c3d4", "changed", "open"))
    for i in range(40):
        con.execute("insert into ids_alerts(ts,sid,signature,severity,category,src,sport,dst,dport,proto,cc) "
                    "values(?,?,?,?,?,?,?,?,?,?,?)", (ts(hours=random.randint(0, 160)), 2000000 + i % 5,
                    random.choice(["ET SCAN Suspicious inbound to mySQL port 3306", "ET POLICY curl User-Agent Outbound",
                                   "ET SCAN NMAP -sS window 1024", "ET DNS Query to a *.top domain"]),
                    random.choice([2, 3]), "scan", random.choice(attackers), 40000 + i, "192.168.1.10", 443, "TCP", "NL"))
    con.execute("insert into intel_hits(ts,device,device_name,kind,indicator,feed,detail) values(?,?,?,?,?,?,?)",
                (ts(hours=9), "192.168.1.31", "bulb-kitchen", "dns", "bad.example.net", "demo-feed", "known C2 domain"))
    con.commit()
    v3(con)
    con.commit()
    v31(con)
    con.commit()
    print(f"demo data written to {config.DB}")


def v3(con):
    """Heartbeat, sign-ins, the device inventory and line health: what the Endpoints columns and the Network map show.
    Pair with tools/demo.yml (hosts, an IoT VLAN, Cloudflare in front) for the full map."""
    import devices
    import heartbeat
    import netwatch
    for m in (heartbeat, devices, netwatch):
        m.db().close()
    beats = [("node:192.168.1.2", "pve1", "node", "192.168.1.2", "up", 1_040_000, None),
             ("ct:100", "proxy", "ct", "192.168.1.2", "up", 1_039_000, None),
             ("ct:101", "dns", "ct", "192.168.1.2", "up", 1_039_000, None),
             ("ct:104", "docker", "ct", "192.168.1.2", "up", 412_000, None),
             ("ct:105", "media", "ct", "192.168.1.2", "up", 170_000, None),
             ("ct:107", "old-wiki", "ct", "192.168.1.2", "stopped", None, "stopped"),
             ("host:192.168.1.5", "nas", "host", None, "up", 262_000, None),
             ("host:192.168.1.7", "llm", "host", None, "down", None, "ssh: connect to host 192.168.1.7 port 22: No route to host")]
    for tgt, name, kind, node, state, up, note in beats:
        down = state == "down"
        con.execute("insert into hb(target,name,kind,node,state,last_ok,last_try,misses,rtt_ms,uptime_s,note,alerted,down_since) "
                    "values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tgt, name, kind, node if kind == "ct" else tgt.split(":")[1], state,
                     ts(minutes=26) if down else ts(minutes=2), ts(minutes=2), 5 if down else 0, None if down else 180,
                     up, note or "", 1 if down else 0, ts(minutes=11) if down else None))
    for when, tgt, ev, det in ((ts(minutes=11), "host:192.168.1.7", "down", "ssh: No route to host"),
                               (ts(days=3), "host:192.168.1.5", "rebooted", "up 2m (was 41d 6h)"),
                               (ts(days=2, hours=4), "ct:105", "back", "after ~6 min")):
        con.execute("insert into hb_events(ts,target,event,detail) values(?,?,?,?)", (when, tgt, ev, det))
    laptop = "SHA256:demoLaptopKey"
    signins = [("node:192.168.1.2", ts(hours=2), "root", "192.168.1.40", "publickey", laptop, 1, 0, 0),
               ("host:192.168.1.5", ts(days=1, hours=3), "admin", "192.168.1.40", "publickey", laptop, 1, 0, 0),
               ("ct:104", ts(days=9), "root", "tty1", "console", "", 1, 0, 0),
               ("ct:100", ts(minutes=40), "root", "100.64.0.7", "publickey", "SHA256:demoUnknownKey", 1, 0, 1)]
    signins += [("host:192.168.1.5", ts(hours=5, minutes=i), u, "192.168.10.23", "password", "", 0, 0, 0)
                for i, u in enumerate(["root", "admin", "admin", "pi", "ubnt", "root"])]
    signins += [(t, ts(minutes=m), "root", "192.168.1.10", "publickey", "SHA256:wardenOwnKey", 1, 1, 0)
                for t in ("node:192.168.1.2", "host:192.168.1.5") for m in (5, 20, 35)]
    for tgt, when, user, src, method, fp, ok, self_, new in signins:
        con.execute("insert or ignore into logins(target,ts,user,src,method,key_fp,ok,self,new) values(?,?,?,?,?,?,?,?,?)",
                    (tgt, when, user, src, method, fp, ok, self_, new))
        con.execute("insert into login_pairs values(?,?,?,?,?,?,?,1,?) on conflict(target,user,src,key_fp,ok) do update "
                    "set last_ts=max(login_pairs.last_ts, excluded.last_ts), n=login_pairs.n+1",
                    (tgt, user, src, fp, ok, when, when, self_))
    for tgt, *_ in beats:
        con.execute("insert or replace into login_runs values(?,?,?,?)", (tgt, ts(minutes=4), "ok", "demo"))
    kinds = [("bulb", 12, 10), ("plug", 5, 10), ("speaker", 4, 1), ("tv", 2, 1), ("camera", 3, 10), ("personal", 5, 1),
             ("computer", 3, 1), ("printer", 1, 1), ("network", 3, 1), ("server", 3, 1), ("unknown", 2, 10)]
    n = 0
    for kind, count, net in kinds:
        for i in range(count):
            n += 1
            ip = f"192.168.{net}.{20 + n}"
            con.execute("insert into devices(mac,ip,name,room,kind,kind_why,fixed,maker,model,sources,first_seen,last_seen,"
                        "updated,identity) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (f"aa:00:00:00:01:{n:02x}", ip, f"{kind}-{i + 1}", random.choice(["Kitchen", "Lounge", "Office", ""]),
                         kind, "demo", 1 if kind in ("bulb", "plug", "camera", "tv", "speaker", "printer") else 0, "Demo Co",
                         "", "sweep,leases", ts(days=30), ts(minutes=random.randint(1, 30)), ts(minutes=1),
                         f"aa:00:00:00:01:{n:02x}"))
    for m in range(60):
        con.execute("insert into net_health values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ((NOW - timedelta(minutes=m)).timestamp(), 0, 0.6, 0, 14 + random.random() * 3, 9, 12, 140, None, None,
                     round(30 + random.random() * 20, 1), round(4 + random.random() * 3, 1), "ok", "[]"))


def v31(con):
    """v3.1: the incident brain (shadow) and generic agent tracking — map, access, destination history."""
    con.executescript("""
      create table if not exists incidents(id integer primary key, entity text, kind text, opened text, last_seen text,
        n_facts integer default 0, weight integer default 0, owner_label text, owner_source text);
      create table if not exists incident_facts(incident_id integer, fact_id text, ts text, source text, summary text,
        weight integer, data text, primary key(incident_id, fact_id));
      create table if not exists incident_decisions(id integer primary key, incident_id integer, ts text, model text,
        facts_hash text, status text, action text, confidence real, why text, cited text, reason text,
        tokens_in integer, tokens_out integer, cost real);
      create table if not exists agent_seen(agent text primary key, first_seen text, last_seen text, host text);
      create table if not exists agent_conns(agent text, host text, dest text, dest_ip text, port integer,
        domain text, first_seen text, last_seen text, hits integer default 1, container text, sample_cmd text,
        bytes_recv integer default 0, primary key(agent, dest, port));
      create table if not exists agent_alerts(id integer primary key, ts text, agent text, host text, dest text,
        dest_ip text, kind text, feed text, detail text, notified integer default 0, unique(agent, dest_ip, feed));
      create table if not exists agent_findings(id integer primary key, ts text, agent text, host text, dest text,
        score integer, decision text, reasons text, facts text, explain text, message_id text, verdict text,
        decided_at text, unique(agent, dest));
      create table if not exists agent_runs(host text primary key, ts text, status text, note text,
        seen integer, attributed integer);
      create table if not exists agent_perms(agent text, host text, ts text, user text, uid integer, gid integer,
        groups text, caps text, sudo text, root integer, primary key(agent, host));
      create table if not exists agent_files(host text, path text, stat text, ts text, primary key(host, path));
    """)
    # ── incidents (shadow): every detector joined per entity; the model's would-be action is recorded, never run ──
    incs = [
        ("203.0.113.0/24", "subnet", 31, 9, None, None,
         [("edge", "14 WAF blocks for /.env and /.git across 3 origins", 4),
          ("log", "path traversal + SQLi from 203.0.113.9 and 203.0.113.41", 4),
          ("geo", "all 8 addresses geolocate to a red-list country", 2)],
         ("ok", "propose_edge_block", 0.82, "Co-ordinated probing from one /24 across edge and origin; recommend an edge block for review.")),
        ("host:192.168.1.5", "box", 12, 7, "benign", "owner ✅ 2 days ago",
         [("vuln", "1 known-exploited CVE with a fix (CISA KEV)", 4),
          ("endpoint", "6 failed SSH sign-ins then a new key accepted", 3)],
         ("ok", "ask_owner", 0.6, "A KEV with a fix on an internet-reachable box, plus an unfamiliar new key — worth a human look.")),
        ("192.168.10.31", "device", 5, 4, None, None,
         [("intel", "kitchen bulb looked up a known-C2 domain", 3),
          ("device", "first new domain this device has ever requested", 2)],
         ("ok", "watch", 0.44, "Likely a firmware call-home, but it is new for this device; watch rather than act.")),
    ]
    for i, (entity, kind, weight, nf, ol, osrc, facts, dec) in enumerate(incs, 1):
        con.execute("insert into incidents(id,entity,kind,opened,last_seen,n_facts,weight,owner_label,owner_source) "
                    "values(?,?,?,?,?,?,?,?,?)", (i, entity, kind, ts(days=2), ts(hours=i), nf, weight, ol, osrc))
        for j, (src, summary, w) in enumerate(facts):
            con.execute("insert into incident_facts(incident_id,fact_id,ts,source,summary,weight,data) values(?,?,?,?,?,?,?)",
                        (i, f"{src}:{i}:{j}", ts(hours=i, minutes=j * 7), src, summary, w, "{}"))
        st, action, conf, why = dec
        con.execute("insert into incident_decisions(incident_id,ts,model,facts_hash,status,action,confidence,why,cited,"
                    "reason,tokens_in,tokens_out,cost) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (i, ts(hours=i), "demo-model", f"h{i}", st, action, conf, why, "[]", "", 300, 40, 0.0002))
    # ── agents: who talks to what, with bytes, known-bad, access, and a map's worth of edges ──
    host = "warden-host"
    agents = [
        ("hermes:scout", 0, 0, "000001ffffffffff", "", "User warden-scout may run: (ALL) NOPASSWD: /usr/bin/systemctl", 1),
        ("hermes:coder", 1001, 1001, "0000000000000400", "1001 999", "", 0),      # cap_net_bind_service, docker group
        ("opencode:steward", 1002, 1002, "0000000000000000", "1002", "", 0),
        ("app:instagram", 1003, 1003, "0000000000000000", "1003", "", 0),
    ]
    for agent, uid, gid, caps, groups, sudo, root in agents:
        con.execute("insert into agent_seen(agent,first_seen,last_seen,host) values(?,?,?,?)", (agent, ts(days=20), ts(minutes=8), host))
        con.execute("insert into agent_perms(agent,host,ts,user,uid,gid,groups,caps,sudo,root) values(?,?,?,?,?,?,?,?,?,?)",
                    (agent, host, ts(minutes=8), agent.split(":")[-1] if root == 0 else "root", uid, gid, groups, caps, sudo, root))
    for path, stat in (("/opt/warden/warden.yml", "0:0:600"), ("/opt/warden/warden.db", "0:0:640"),
                       ("/home/coder/.env", "1001:999:640")):
        con.execute("insert into agent_files(host,path,stat,ts) values(?,?,?,?)", (host, path, stat, ts(minutes=8)))
    # destinations: (agent, domain, ip, port, hits, bytes, container)
    dests = [
        ("hermes:scout", "openrouter.ai", "198.51.100.7", 443, 420, 2_300_000, ""),
        ("hermes:scout", "api.github.com", "198.51.100.8", 443, 86, 540_000, ""),
        ("hermes:coder", "api.github.com", "198.51.100.8", 443, 310, 61_000_000, "docker-9ad31c2b7e01"),
        ("hermes:coder", "registry.npmjs.org", "198.51.100.12", 443, 140, 48_500_000, "docker-9ad31c2b7e01"),
        ("opencode:steward", "api.openai.com", "198.51.100.21", 443, 72, 1_100_000, ""),
        ("app:instagram", "graph.instagram.com", "198.51.100.33", 443, 55, 260_000, ""),
        ("app:instagram", "", "203.0.113.66", 4444, 3, 900, ""),                   # the known-bad one
    ]
    for agent, domain, ip, port, hits, brecv, ctr in dests:
        dest = domain or ip
        con.execute("insert into agent_conns(agent,host,dest,dest_ip,port,domain,first_seen,last_seen,hits,container,sample_cmd,bytes_recv) "
                    "values(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (agent, host, dest, ip, port, domain, ts(days=15), ts(minutes=9), hits, ctr, agent, brecv))
    con.execute("insert into agent_alerts(ts,agent,host,dest,dest_ip,kind,feed,detail,notified) values(?,?,?,?,?,?,?,?,1)",
                (ts(hours=3), "app:instagram", host, "203.0.113.66", "203.0.113.66", "c2", "feodo", "outbound to 203.0.113.66:4444"))
    con.execute("insert into agent_findings(ts,agent,host,dest,score,decision,reasons,facts,explain,message_id,verdict) "
                "values(?,?,?,?,?,?,?,?,?,?,?)",
                (ts(hours=6), "opencode:steward", host, "api.openai.com", 58, "review",
                 '["a destination this agent has not used before","first seen between midnight and 6am"]', "{}",
                 "Could be a new model backend; check the run that opened it.", "demo-mid", None))
    for h in (host,):
        con.execute("insert into agent_runs(host,ts,status,note,seen,attributed) values(?,?,?,?,?,?)",
                    (h, ts(minutes=8), "ok", "root; 28/34 sockets attributed", 34, 28))


if __name__ == "__main__":
    main()
