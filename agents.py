#!/usr/bin/env python3
"""agents.py — which Hermes agent is talking to what, and is any of them reaching a known-bad host?

The estate runs autonomous AI agents: the Hermes profiles (coder, writer, scout, sec, seo, …), the OpenCode/steward
coding agent, and app agents like the scraper, the listing desk and the Instagram agent. A prompt-injected or
compromised agent beaconing or exfiltrating looks, from the network, like any other HTTPS. This attributes each
outbound connection to the AGENT that made it, checks every destination against the same threat feeds netintel
uses, and — after a short learning window — flags a Hermes agent reaching a destination it has never used before.
Detect-only: it reads `/proc` and sockets, never blocks or kills.

Interactive developer tools (e.g. Claude Code) are deliberately OUT of scope — this watches the AUTONOMOUS agents,
not a person at a keyboard. They, plus ssh/sshd and system daemons, are skipped via `agents.ignore`.

Where it looks: the box warden runs on (always, unless `agents.include_local: false`) plus any declared host with
`agents: true`. On each, ONE read-only collector reads established outbound sockets (`ss -tnp`) and attributes each
to a process via `/proc/<pid>` — then the agent is named from the process command line:
    hermes --profile coder   -> hermes:coder        opencode run …   -> opencode:<user>
    a .py app agent          -> app:<script>        anything else    -> other:<exe>

  agents.py            collect, attribute, threat-check, score new destinations, ask on the odd ones (timer: 10 min)
  agents.py --dry      collect and print what each agent is talking to, write nothing, post nothing
  agents.py --list     the current agent→destination table
  agents.py --feeds    force-refresh the threat feeds (shared with netintel)

Threat match is on the destination IP (Feodo C2, FireHOL level-1) and, when the host's resolver log lets us map the
IP back to a name, on the domain (URLhaus, ThreatFox, OpenPhish) and the red-list countries — reusing netintel's
feeds and matchers. A feed hit is an `agent_alert` (highest priority). A merely NEW destination is scored like
devicewatch and only the odd ones raise a Discord ✅/❌ card. `ss` is a snapshot, so a connection that opens and
closes between polls is missed; without root only warden's own user's sockets carry process info (reported, never
guessed). No model gathers facts; the Hermes read on a review card is advisory and labelled.
"""
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netintel  # noqa: E402   (feeds + matchers: refresh_feeds, load_feeds, ip_in, match_domain)
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
LOG_AT, REVIEW_AT = 25, 55
LEARN_HOURS = int(config.get("agents.learn_hours") or 48)      # a dest first seen within this of an agent's first
RISKY_TLD = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "click", "work", "icu", "cyou", "buzz", "rest", "zip",
             "mov", "ru", "su", "cn"}
TZ = ZoneInfo(config.get("estate.timezone") or "Europe/London")

# One read-only collector. Emits: @@meta, @@total <n>, @@conn <pid> <rip> <rport>, @@proc <pid> <uid> <cg> <exe> <cmd>.
COLLECT = r'''LC_ALL=C; export LC_ALL
printf '@@meta\thost=%s\troot=%s\tss=%s\n' "$(hostname 2>/dev/null)" \
  "$([ "$(id -u)" = 0 ] && echo 1 || echo 0)" "$(command -v ss >/dev/null 2>&1 && echo 1 || echo 0)"
command -v ss >/dev/null 2>&1 || exit 0
printf '@@total\t%s\n' "$(ss -tnH state established 2>/dev/null | wc -l)"
ss -tnpH state established 2>/dev/null | while IFS= read -r line; do
  peer=$(printf '%s\n' "$line" | awk '{print $4}')
  case "$peer" in *:*) : ;; *) continue ;; esac
  rip=${peer%:*}; rport=${peer##*:}; rip=${rip#[}; rip=${rip%]}
  for p in $(printf '%s\n' "$line" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    printf '@@conn\t%s\t%s\t%s\n' "$p" "$rip" "$rport"
  done
done
for p in $(ss -tnpH state established 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un); do
  [ -r /proc/$p/cmdline ] || continue
  uid=$(awk '/^Uid:/{print $2; exit}' /proc/$p/status 2>/dev/null)
  exe=$(readlink /proc/$p/exe 2>/dev/null)
  cg=$(grep -ao 'docker[-/][0-9a-f]\{12,64\}\|lxc[-/.][A-Za-z0-9_-]*' /proc/$p/cgroup 2>/dev/null | head -1)
  cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-240)
  printf '@@proc\t%s\t%s\t%s\t%s\t%s\n' "$p" "$uid" "$cg" "$exe" "$cmd"
done
true
'''


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists agent_seen(agent text primary key, first_seen text, last_seen text, host text);
      create table if not exists agent_conns(agent text, host text, dest text, dest_ip text, port integer,
        domain text, first_seen text, last_seen text, hits integer default 1, container text, sample_cmd text,
        primary key(agent, dest, port));
      create index if not exists ac_agent on agent_conns(agent);
      create table if not exists agent_alerts(id integer primary key, ts text, agent text, host text, dest text,
        dest_ip text, kind text, feed text, detail text, notified integer default 0, unique(agent, dest_ip, feed));
      create table if not exists agent_findings(id integer primary key, ts text, agent text, host text, dest text,
        score integer, decision text, reasons text, facts text, explain text, message_id text, verdict text,
        decided_at text, unique(agent, dest));
      create table if not exists agent_runs(host text primary key, ts text, status text, note text,
        seen integer, attributed integer);
    """)
    return con


# ── not tracked ─────────────────────────────────────────────────────────────────
# Interactive dev tools (Claude Code) and plain ssh/system noise are out of scope: this watches autonomous agents.
# Owner can extend with `agents.ignore: [pattern, ...]` (substring or /regex/ against the command line).
IGNORE_DEFAULT = [r"\bclaude\b", r"claude-code", r"@anthropic-ai/claude-code", r"(^|/)sshd?\b", r"/usr/lib/systemd",
                  r"\bsystemd(-\w+)?\b", r"\b(cron|dbus-daemon|rsyslogd|chronyd|systemd-timesyncd)\b"]


def _ignore_patterns():
    pats = list(IGNORE_DEFAULT)
    for p in (config.get("agents.ignore") or []):
        pats.append(p[1:-1] if len(p) > 1 and p[0] == p[-1] == "/" else re.escape(p))
    return [re.compile(p) for p in pats]


IGNORE = _ignore_patterns()


def ignored(cmd):
    return any(rx.search(cmd or "") for rx in IGNORE)


# ── who is this agent? ─────────────────────────────────────────────────────────
# (compiled pattern over the command line, a namer). First match wins; order matters. Hermes profiles first.
CLASSIFY = [
    (re.compile(r"\bhermes\b"),          lambda m, cmd, u: "hermes:" + (re.search(r"--profile[= ]+(\S+)", cmd).group(1)
                                                                        if re.search(r"--profile[= ]+(\S+)", cmd) else "default")),
    (re.compile(r"\bopencode\b"),        lambda m, cmd, u: "opencode:" + (u or "?")),
    (re.compile(r"\bollama\b"),          lambda m, cmd, u: "ollama"),
    (re.compile(r"crawl4ai|playwright|chromium|headless"),                  lambda m, cmd, u: "app:scraper"),
]


def classify(cmd, exe="", uid_name=""):
    """(agent, why). From the process command line; Python scripts become app:<script>, everything else other:<exe>."""
    cmd = cmd or ""
    for rx, name in CLASSIFY:
        if rx.search(cmd):
            label = rx.pattern.split("|")[0].strip("\\b").strip("()^$")
            return name(None, cmd, uid_name), f"matched '{label}' in command"
    m = re.search(r"(?:^|\s)(?:python3?|python3\.\d+)\s+(?:-[A-Za-z]+\s+)*(?:-m\s+(\S+)|(\S+\.py))", cmd)
    if m:
        mod = (m.group(1) or os.path.basename(m.group(2) or "")).rsplit(".", 1)[0]
        return f"app:{mod}", "python script/module"
    base = os.path.basename(exe or (cmd.split() or [""])[0]) or "unknown"
    return f"other:{base}", "unclassified process"


# ── collection ──────────────────────────────────────────────────────────────────
def _addr(ssh):
    return (ssh or "").split("@")[-1]


def agent_targets():
    """The box warden runs on (unless opted out) plus declared hosts with `agents: true`."""
    out, seen = [], set()
    if config.get("agents.include_local", True):
        out.append({"target": "host:local", "kind": "local", "name": config.get("agents.local_name") or "this box", "ssh": ""})
        seen.add("host:local")
    decl = {(h.get("name") or _addr(h.get("ssh"))): h for h in hosts.declared()}
    for t in hosts.targets(discover=False):
        if t["kind"] in ("node", "host", "local") and (decl.get(t["name"]) or {}).get("agents") and t["target"] not in seen:
            out.append(t); seen.add(t["target"])
    return out


def collect(t):
    """(meta, conns, procs) from one host. conns: [(pid,rip,rport)]; procs: {pid:(uid,container,exe,cmd)}."""
    rc, out, err = hosts.remote(t, COLLECT, timeout=120, root=t["kind"] in ("host", "local", "node", "ct"))
    meta = {"host": t["name"], "root": False, "ss": False, "total": 0, "err": (err or "").strip()[:160] if rc else ""}
    conns, procs = [], {}
    for line in (out or "").splitlines():
        f = line.split("\t")
        if f[0] == "@@meta":
            for kv in line.split("\t")[1:]:
                k, _, v = kv.partition("=")
                if k == "host" and v:
                    meta["host"] = v
                elif k in ("root", "ss"):
                    meta[k] = v == "1"
        elif f[0] == "@@total" and len(f) > 1:
            meta["total"] = int(f[1]) if f[1].isdigit() else 0
        elif f[0] == "@@conn" and len(f) == 4:
            conns.append((f[1], f[2], f[3]))
        elif f[0] == "@@proc" and len(f) >= 6:
            procs[f[1]] = (f[2], f[3], f[4], "\t".join(f[5:]))
    meta["rc"] = rc
    return meta, conns, procs


def is_internet(ip):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.version == 4 and a.is_global and not (a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def uid_name(uid):
    try:
        import pwd
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, OverflowError):
        return uid or ""


# ── scoring a NEW destination (mirrors devicewatch) ──────────────────────────────
def score(f):
    s, why = 40, ["a destination this agent has not used before"]
    if f["other_agents_using_it"] == 0:
        s += 20; why.append("no other agent uses it")
    elif f["other_agents_using_it"] >= 2:
        s -= 25; why.append(f"{f['other_agents_using_it']} other agents already use it")
    if f["hour"] < 6:
        s += 15; why.append("first seen between midnight and 6am")
    if f["tld"] and f["tld"] in RISKY_TLD:
        s += 20; why.append(f".{f['tld']} is a high-abuse TLD")
    if not f["domain"]:
        s += 10; why.append("a raw IP with no resolved name")
    if f["port"] not in (443, 80):
        s += 10; why.append(f"port {f['port']} (not plain web)")
    return max(0, min(100, s)), why


def decision(s):
    return "review" if s >= REVIEW_AT else "logged" if s >= LOG_AT else "learned"


def explain(f):
    """Advisory plain-English read from the Hermes `sec` agent; '' if unavailable. Facts never come from it."""
    import subprocess
    prompt = ("You review a homelab's own autonomous AI agents. One Hermes-estate agent connected to a destination it has never used. Using ONLY "
              "these facts (add none), write at most two short sentences: the innocent and the worrying explanation if "
              "both fit, and one concrete thing to check. Be measured; never say 'compromised' or 'almost certainly'. "
              "Do not repeat the facts. Facts: " + json.dumps(f))
    try:
        p = subprocess.run(["/usr/local/bin/hermes", "--profile", config.get("agents.hermes_profile") or "sec", "-z",
                            prompt], capture_output=True, text=True, timeout=180, cwd="/root")
        out = re.sub(r"\s+", " ", (p.stdout or "").replace("**", "")).strip()
        txt = " ".join(re.split(r"(?<=[.!?])\s+", out)[:2])
        return (txt[:450].rsplit(" ", 1)[0] + "…") if len(txt) > 450 else (txt if p.returncode == 0 and out else "")
    except Exception:  # noqa: BLE001
        return ""


def card(f, s, why, read):
    return (f"🕵️ **New destination for `{f['agent']}`** on {f['host']} → `{f['dest']}`"
            f"{' :' + str(f['port']) if f['port'] not in (443, 80) else ''} · {f['first_seen_local']}\n"
            f"Score **{s}**: {'; '.join(why)}.\nUsually talks to: {f['usual'] or 'nothing else yet'}\n"
            + (f"Hermes (advisory): {read}\n" if read else "")
            + "✅ = expected, learn it · ❌ = not expected, I'll look")


# ── run ───────────────────────────────────────────────────────────────────────
def run(dry=False):
    con = db()
    netintel.refresh_feeds("--feeds" in sys.argv)
    domains, v4 = netintel.load_feeds()
    geo = redlist = None
    try:
        from geo import Geo
        geo = Geo(config.DATA)
        redlist = {c for c in (_redlist_watch())}
    except Exception:  # noqa: BLE001
        pass
    ts = now()
    counts = {"learned": 0, "logged": 0, "review": 0, "alerts": 0, "conns": 0}
    reviews, alerts = [], []
    for t in agent_targets():
        meta, conns, procs = collect(t)
        host = meta["host"]
        if meta["rc"] and not conns:
            con.execute("insert into agent_runs(host,ts,status,note,seen,attributed) values(?,?,?,?,?,?) "
                        "on conflict(host) do update set ts=excluded.ts,status=excluded.status,note=excluded.note,"
                        "seen=excluded.seen,attributed=excluded.attributed",
                        (host, ts, "error", meta["err"] or f"exit {meta['rc']}", 0, 0))
            continue
        attributed = {c[0] for c in conns if c[0] in procs}
        for pid, rip, rport in conns:
            if not is_internet(rip) or pid not in procs:
                continue
            uid, cg, exe, cmd = procs[pid]
            if ignored(cmd):                                   # Claude Code, ssh, system daemons — not autonomous agents
                continue
            agent, _ = classify(cmd, exe, uid_name(uid))
            port = int(rport) if rport.isdigit() else 0
            dom = ""                                           # best-effort name; raw IP otherwise
            dest = dom or rip
            counts["conns"] += 1
            con.execute("insert into agent_seen(agent,first_seen,last_seen,host) values(?,?,?,?) on conflict(agent) "
                        "do update set last_seen=excluded.last_seen", (agent, ts, ts, host))
            con.execute("""insert into agent_conns(agent,host,dest,dest_ip,port,domain,first_seen,last_seen,hits,container,sample_cmd)
                           values(?,?,?,?,?,?,?,?,1,?,?) on conflict(agent,dest,port) do update set
                           last_seen=excluded.last_seen, hits=agent_conns.hits+1, host=excluded.host""",
                        (agent, host, dest, rip, port, dom, ts, ts, cg, cmd[:200]))
            # ── threat match (highest priority) ──
            hit = []
            f_ip = netintel.ip_in(v4, rip)
            if f_ip:
                hit.append(("c2" if f_ip == "feodo" else "badip", f_ip, f"outbound to {rip}:{port}"))
            if dom:
                d, feed = netintel.match_domain(dom, domains)
                if d:
                    kind = "phishing" if feed == "openphish" else "malware"
                    hit.append((kind, feed, f"looked up {dom}"))
            if geo and redlist:
                cc = geo.cc(rip)
                if cc in redlist:
                    hit.append(("redlist", "geo", f"traffic to {cc}"))
            for kind, feed, detail in hit:
                cur = con.execute("insert or ignore into agent_alerts(ts,agent,host,dest,dest_ip,kind,feed,detail) "
                                  "values(?,?,?,?,?,?,?,?)", (ts, agent, host, dest, rip, kind, feed, detail))
                if cur.rowcount:
                    alerts.append((con.execute("select last_insert_rowid()").fetchone()[0], agent, host, dest, kind, feed, detail))
            if hit:
                continue                                       # a known-bad dest is alerted, not also "scored as new"
            # ── anomaly: a destination new for an agent past its learning window ──
            seen = con.execute("select first_seen from agent_seen where agent=?", (agent,)).fetchone()
            first_dest = con.execute("select first_seen from agent_conns where agent=? and dest=? and port=?",
                                     (agent, dest, port)).fetchone()
            learned_by = _hours_between(seen["first_seen"], first_dest["first_seen"]) >= LEARN_HOURS if seen and first_dest else False
            if not learned_by:
                continue
            if con.execute("select 1 from agent_findings where agent=? and dest=?", (agent, dest)).fetchone():
                continue
            others = con.execute("select count(distinct agent) from agent_conns where dest=? and agent!=?", (dest, agent)).fetchone()[0]
            usual = ", ".join(f"`{r[0]}`" for r in con.execute(
                "select dest from agent_conns where agent=? and dest!=? order by hits desc limit 5", (agent, dest)))
            lt = datetime.strptime(first_dest["first_seen"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(TZ)
            f = {"agent": agent, "host": host, "dest": dest, "port": port, "domain": dom,
                 "tld": dom.rsplit(".", 1)[-1] if "." in dom else "", "hour": lt.hour,
                 "first_seen_local": lt.strftime("%a %d %b %H:%M"), "other_agents_using_it": others, "usual": usual}
            s, why = score(f)
            d = decision(s)
            counts[d] += 1
            if dry:
                if d != "learned":
                    print(f"{d:<7} {s:>3}  {agent:<18} {dest:<30} {'; '.join(why[1:])}")
                continue
            con.execute("insert into agent_findings(ts,agent,host,dest,score,decision,reasons,facts) values(?,?,?,?,?,?,?,?)",
                        (ts, agent, host, dest, s, d, json.dumps(why), json.dumps(f)))
            if d == "review":
                reviews.append((con.execute("select last_insert_rowid()").fetchone()[0], f, s, why))
        con.execute("insert into agent_runs(host,ts,status,note,seen,attributed) values(?,?,?,?,?,?) "
                    "on conflict(host) do update set ts=excluded.ts,status=excluded.status,note=excluded.note,"
                    "seen=excluded.seen,attributed=excluded.attributed",
                    (host, ts, "ok", ("root" if meta["root"] else "no root — only warden's own sockets")
                     + (f"; {len(attributed)}/{meta['total']} sockets attributed" if meta["total"] else ""),
                     meta["total"], len(attributed)))
    counts["alerts"] = len(alerts)
    if dry:
        print("agents (dry):", " ".join(f"{k}={v}" for k, v in counts.items()))
        return 0
    con.commit()                                               # commit BEFORE any notify call
    for aid, agent, host, dest, kind, feed, detail in alerts:
        mid = notify.post(f"🚨 **Hermes agent reached a known-bad destination** — `{agent}` on {host}\n"
                          f"{kind.upper()} ({feed}): {detail}\nThis is detect-only; warden did not block it. "
                          f"Check what {agent} is doing and why.")
        con.execute("update agent_alerts set notified=1 where id=?", (aid,)); con.commit()
        del mid
    for fid, f, s, why in reviews[:5]:
        read = explain(f)
        mid = notify.post(card(f, s, why, read))
        notify.react(mid, notify.APPROVE); notify.react(mid, notify.REJECT)
        con.execute("update agent_findings set explain=?, message_id=? where id=?", (read, mid, fid)); con.commit()
    poll(con)
    print("agents:", " ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


def poll(con):
    for r in con.execute("select id, message_id from agent_findings where decision='review' and verdict is null "
                         "and message_id is not null").fetchall():
        yes = notify.reactors(r["message_id"], notify.APPROVE)
        no = notify.reactors(r["message_id"], notify.REJECT)
        if yes is None:
            con.execute("update agent_findings set verdict='dropped', decided_at=datetime('now') where id=?", (r["id"],))
        elif notify.owner() in (no or []):
            con.execute("update agent_findings set verdict='suspicious', decided_at=datetime('now') where id=?", (r["id"],))
            con.commit(); notify.resolve(r["message_id"], "❌ not expected — flagged")
        elif notify.owner() in yes:
            con.execute("update agent_findings set verdict='normal', decided_at=datetime('now') where id=?", (r["id"],))
            con.commit(); notify.resolve(r["message_id"], "✅ expected, learned")
    con.commit()


def _hours_between(a, b):
    try:
        da = datetime.strptime(a, "%Y-%m-%d %H:%M:%S"); db_ = datetime.strptime(b, "%Y-%m-%d %H:%M:%S")
        return abs((db_ - da).total_seconds()) / 3600.0
    except (ValueError, TypeError):
        return 0.0


def _redlist_watch():
    try:
        import yaml
        p = config.HOME / "redlist.yml"
        d = yaml.safe_load(open(p)) if p.exists() else {}
        return [c.upper() for c in (d.get("watch") or [])]
    except Exception:  # noqa: BLE001
        return []


def main():
    a = sys.argv[1:]
    con = db()
    if "--list" in a:
        for r in con.execute("select agent, host, count(*) dests, sum(hits) hits, max(last_seen) last "
                             "from agent_conns group by agent order by agent"):
            print(f"{r['agent']:<20} {r['host']:<16} {r['dests']:>3} dests  {r['hits']:>6} conns  last {r['last']}")
        return 0
    return run(dry="--dry" in a)


if __name__ == "__main__":
    sys.exit(main())
