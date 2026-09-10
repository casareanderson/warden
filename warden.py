#!/usr/bin/env python3
"""warden — in-house intrusion detection + ban proposal for the homelab.

A local, dependency-free complement to CrowdSec. It reads the logs that
CrowdSec either cannot see or does not parse, scores hostile behaviour, and
proposes bans. It is a SECOND OPINION, not a replacement: CrowdSec keeps
running, and warden's findings are independent of it.

⛔ WHY THERE IS NO iptables/nftables CODE IN HERE
Everything external arrives through the Cloudflare tunnel. At layer 3 the
source address is cloudflared / the Cloudflare edge — the attacker's real IP
exists ONLY in the HTTP layer (CF-Connecting-IP, which NPMplus logs as its
4th field). So:
  - a local IP ban keyed on the attacker's address would never match a packet;
  - banning what DOES appear at L3 would ban Cloudflare and black-hole the
    entire estate.
Enforcement therefore happens at the Cloudflare EDGE (IP Access Rules), before
traffic ever enters the tunnel. That is the only layer where the attacker's
address is both visible and blockable.

⚠️ SAFETY: warden ships in DETECT-ONLY mode. It records what it *would* ban and
enforces nothing until `enforce: true` is set in warden.yml. A tool that can
lock the owner out of his own estate does not get to do that on its first run.
"""
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "data" / "warden.db"
CONF = BASE / "warden.yml"
# The host holding the log-source containers, reached over SSH. Set it
# for your estate; the collectors below run `docker exec` on it. There is
# nothing magic about SSH+docker here - swap the collectors for however
# your logs are reachable.
LOG_HOST = os.environ.get("WARDEN_LOG_HOST", "")

# ---------------------------------------------------------------- config ---
def load_conf():
    """Deliberately tiny YAML subset — no PyYAML dependency on this box."""
    cfg = {
        "enforce": False, "ban_threshold": 12, "max_bans_per_run": 3,
        "window_minutes": 60, "allow": [], "ban_hours": 24,
        "subnet_threshold": 20, "subnet_min_ips": 3,
    }
    if not CONF.exists():
        return cfg
    key = None
    for raw in CONF.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and key:
            cfg.setdefault(key, []).append(line[4:].strip().strip('"\''))
            continue
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip().strip('"\'')
            key = k
            if v == "":
                cfg[k] = []
            elif v.lower() in ("true", "false"):
                cfg[k] = v.lower() == "true"
            elif v.isdigit():
                cfg[k] = int(v)
            else:
                cfg[k] = v
    return cfg

# ------------------------------------------------------------- allowlist ---
# Cloudflare's published ranges. Banning these = banning the front door.
CLOUDFLARE = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]

def net_overlaps_allow(net_str, extra):
    """True if a candidate ban RANGE touches any allowlisted address or range.

    ⚠️⚠️ THE PER-IP ALLOWLIST CHECK IS NOT ENOUGH FOR A /24. The subnet roll-up
    filters allowlisted IPs out of the SCORE, but the range it then proposes can
    still CONTAIN an allowlisted address - your own IP sitting in an otherwise
    noisy /24. Banning that /24 at the edge black-holes your own address along
    with the noise. So a range ban is refused if it overlaps anything allowed.
    """
    try:
        cand = ip_network(net_str, strict=False)
    except ValueError:
        return True                      # unparseable candidate -> never ban
    for cidr in PRIVATE + CLOUDFLARE + list(extra):
        try:
            other = (ip_network(cidr, strict=False) if "/" in cidr
                     else ip_network(cidr + "/32"))
            if cand.overlaps(other):
                return True
        except ValueError:
            continue
    return False


def is_allowlisted(ip, extra):
    try:
        a = ip_address(ip)
    except ValueError:
        return True  # unparseable → never act on it
    for cidr in PRIVATE + CLOUDFLARE + list(extra):
        try:
            net = ip_network(cidr, strict=False) if "/" in cidr else None
            if net and a in net:
                return True
            if net is None and str(a) == cidr:
                return True
        except ValueError:
            continue
    return False

# ------------------------------------------------------------------ db ----
SCHEMA = """
create table if not exists events(
  id integer primary key, ts text, source text, ip text,
  kind text, detail text, score integer);
create table if not exists bans(
  id integer primary key, ts text, ip text, score integer,
  reasons text, state text, expires text, note text);
create table if not exists watermarks(source text primary key, pos text);
create table if not exists seen(h text primary key, ts text);
create table if not exists runs(
  id integer primary key, ts text, source text, lines integer,
  parsed integer, note text);
create index if not exists ev_ip on events(ip);
create index if not exists ev_ts on events(ts);
"""

def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=20)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con

def wm_get(con, src):
    r = con.execute("select pos from watermarks where source=?", (src,)).fetchone()
    return r["pos"] if r else None

def wm_set(con, src, pos):
    con.execute("insert into watermarks(source,pos) values(?,?) "
                "on conflict(source) do update set pos=excluded.pos", (src, str(pos)))

# ------------------------------------------------------------- collectors --
def zssh(cmd, timeout=60):
    """Run a command on the log host over SSH. Complex quoting breaks over this
    hop, so callers keep the commands they pass simple."""
    if not LOG_HOST:
        return ""
    try:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                            LOG_HOST, cmd], capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""

def collect_npm(con):
    """NPMplus access log. Byte-offset watermark; resets on rotation."""
    size = zssh("docker exec npmplus sh -c 'wc -c < /data/nginx/logs/access.log'").strip()
    if not size.isdigit():
        return [], 0
    size = int(size)
    pos = int(wm_get(con, "npm") or 0)
    if size < pos:            # rotated
        pos = 0
    if size == pos:
        return [], 0
    chunk = zssh(f"docker exec npmplus sh -c 'tail -c +{pos+1} /data/nginx/logs/access.log'")
    wm_set(con, "npm", size)
    return chunk.splitlines(), size - pos

# NPMplus format. NOTE the bracketed timestamp CONTAINS A SPACE, so the client
# IP is the 4th whitespace field, not the 3rd. Getting this wrong makes the
# vhost look like the client and hides every real address.
NPM_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+(?P<host>\S+)\s+(?P<ip>\S+)\s+(?P<rt>\S+)\s+'
    r'"(?P<verb>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+\S+\s+\S+\s+'
    r'(?P<ref>\S+)\s+(?P<ua>.*)$')

AUTH_FAIL = re.compile(r'remote_ip=(?P<ip>[0-9a-fA-F:.]+)')
CFD_RE = re.compile(r'dest=https?://(?P<host>[^/\s]+)(?P<path>\S*)')

def collect_authelia(con):
    size = zssh("docker exec crowdsec sh -c 'wc -c < /acquis/authelia.log'").strip()
    if not size.isdigit():
        return [], 0
    size = int(size); pos = int(wm_get(con, "authelia") or 0)
    if size < pos: pos = 0
    if size == pos: return [], 0
    chunk = zssh(f"docker exec crowdsec sh -c 'tail -c +{pos+1} /acquis/authelia.log'")
    wm_set(con, "authelia", size)
    return chunk.splitlines(), size - pos

def collect_cloudflared(con):
    """The tunnel's own log — the ONLY place that sees hostnames routed direct
    to an origin, bypassing NPMplus. Nothing else in the estate reads it.

    The watermark is a real RFC3339 timestamp, not a fixed '10m' lookback: with
    a 5-minute timer a fixed 10-minute window re-reads half of every previous
    run, double-counting each attack and inflating scores toward a false ban.
    """
    since = wm_get(con, "cloudflared") or "10m"
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = zssh(f"docker logs cloudflared --since {since} 2>&1 | tail -400")
    wm_set(con, "cloudflared", started)
    return out.splitlines(), len(out)

# ------------------------------------------------------------------ rules --
HOSTILE_PATH = [
    (re.compile(r'\.\./|%2e%2e', re.I),                 6, "path-traversal"),
    (re.compile(r'/etc/passwd|/etc/shadow', re.I),      8, "sensitive-file"),
    (re.compile(r'@fs/', re.I),                         7, "vite-fs-read"),
    (re.compile(r'/\.env|/\.git/|/\.aws/', re.I),       7, "secret-file-probe"),
    (re.compile(r'/wp-(admin|login|content)', re.I),    3, "wordpress-probe"),
    (re.compile(r'/phpmyadmin|/pma/|/adminer', re.I),   4, "db-admin-probe"),
    (re.compile(r'\.(php|asp|aspx|cgi)($|\?)', re.I),   2, "script-probe"),
    (re.compile(r'/actuator|/console|/solr|/jenkins', re.I), 4, "app-probe"),
    (re.compile(r'union.*select|sleep\(|benchmark\(', re.I), 8, "sqli-attempt"),
]
HOSTILE_UA = re.compile(
    r'sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|curl/7\.\d+ \(internal',
    re.I)

# ⚠️ An event's time is the time in the LOG LINE, never the time we read it.
# First ingest reads a whole backlog at once; if ingestion time were used, weeks
# of history would land inside the "last 60 minutes" window and could trigger a
# ban for something that happened in July. Found exactly that on 2026-08-30.
NPM_TS = re.compile(r'^\[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})')
AUTH_TS = re.compile(r'time="([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8})')
CFD_TS = re.compile(r'^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8})Z')
MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def event_time(src, line):
    """Return the line's own timestamp as 'YYYY-MM-DD HH:MM:SS', or None."""
    try:
        if src == "npm":
            m = NPM_TS.match(line)
            if m:
                d, mon, y, t = m.groups()
                return f"{y}-{MONTHS[mon]:02d}-{d} {t}"
        elif src == "authelia":
            m = AUTH_TS.search(line)
            if m:
                return m.group(1).replace("T", " ")
        elif src == "cloudflared":
            m = CFD_TS.match(line)
            if m:
                return m.group(1).replace("T", " ")
    except Exception:
        pass
    return None


def score_npm(line):
    m = NPM_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    hits, score = [], 0
    for rx, pts, name in HOSTILE_PATH:
        if rx.search(d["path"]):
            score += pts; hits.append(name)
    if HOSTILE_UA.search(d["ua"]):
        score += 5; hits.append("hostile-user-agent")
    if d["status"] in ("404", "403", "401") and score == 0:
        score += 1; hits.append("4xx")
    if not hits:
        return None
    return dict(ip=d["ip"], kind=",".join(hits), score=score,
                detail=f'{d["verb"]} {d["host"]}{d["path"]} -> {d["status"]} ua={d["ua"][:60]}')

def score_authelia(line):
    if "authentication failed" not in line.lower() and "invalid credentials" not in line.lower():
        return None
    m = AUTH_FAIL.search(line)
    if not m:
        return None
    return dict(ip=m.group("ip"), kind="auth-failure", score=3,
                detail=line[:180])

def score_cloudflared(line):
    m = CFD_RE.search(line)
    if not m:
        return None
    path = m.group("path")
    hits, score = [], 0
    for rx, pts, name in HOSTILE_PATH:
        if rx.search(path):
            score += pts; hits.append(name)
    if not hits:
        return None
    # cloudflared logs the CF EDGE ip (ip=198.41.x.x), never the client's. We
    # record the attack but cannot attribute it — so it scores the target, not
    # an IP we could ban. Attribution has to come from the NPMplus line.
    return dict(ip="", kind=",".join(hits) + ",unattributed",
                score=score, detail=f'{m.group("host")}{path[:120]}')

# ------------------------------------------------------------- enforcement -
def cf_ban(ip, note, cfg):
    """Cloudflare IP Access Rule — block at the edge. Only layer that works."""
    import urllib.request
    tok = os.environ.get("CLOUDFLARE_API_TOKEN")
    acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not tok or not acct:
        return False, "no CF credentials in env"
    # Cloudflare access rules use a different target keyword for a range.
    target = "ip_range" if "/" in ip else "ip"
    body = json.dumps({"mode": "block",
                       "configuration": {"target": target, "value": ip},
                       "notes": f"warden: {note}"[:200]}).encode()
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{acct}/firewall/access_rules/rules",
        data=body, method="POST",
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r).get("success", False), "ok"
    except Exception as e:
        return False, str(e)[:150]

# ------------------------------------------------------------------ main ---
def main():
    cfg = load_conf()
    con = db()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    total_new = 0

    for src, collect, scorer in (
        ("npm", collect_npm, score_npm),
        ("authelia", collect_authelia, score_authelia),
        ("cloudflared", collect_cloudflared, score_cloudflared),
    ):
        lines, nbytes = collect(con)
        parsed = 0
        for ln in lines:
            ev = scorer(ln)
            if not ev:
                continue
            # A log line must never be scored twice. Watermarks handle the
            # normal case; this catches restarts, rotation and any overlap a
            # timestamp-based --since still lets through.
            h = hashlib.sha1(f"{src}\x00{ln}".encode("utf-8", "replace")).hexdigest()
            if con.execute("select 1 from seen where h=?", (h,)).fetchone():
                continue
            con.execute("insert into seen(h,ts) values(?,?)", (h, now))
            parsed += 1
            ets = event_time(src, ln) or now
            con.execute("insert into events(ts,source,ip,kind,detail,score) "
                        "values(?,?,?,?,?,?)",
                        (ets, src, ev["ip"], ev["kind"], ev["detail"], ev["score"]))
        total_new += parsed
        con.execute("insert into runs(ts,source,lines,parsed,note) values(?,?,?,?,?)",
                    (now, src, len(lines), parsed, f"{nbytes}B"))
    con.execute("delete from seen where ts < datetime('now','-7 days')")
    con.commit()

    # --- decide ---------------------------------------------------------
    win = f"-{cfg['window_minutes']} minutes"
    rows = con.execute(
        "select ip, sum(score) s, count(*) n, group_concat(distinct kind) k "
        "from events where ip!='' and ts > datetime('now',?) group by ip "
        "having s >= ? order by s desc", (win, cfg["ban_threshold"])).fetchall()

    proposed = 0
    for r in rows:
        if is_allowlisted(r["ip"], cfg.get("allow", [])):
            continue
        already = con.execute(
            "select 1 from bans where ip=? and state in ('active','proposed') "
            "and ts > datetime('now','-1 day')", (r["ip"],)).fetchone()
        if already:
            continue
        if proposed >= cfg["max_bans_per_run"]:
            break
        state, note = "proposed", "detect-only (enforce=false)"
        if cfg["enforce"]:
            ok, msg = cf_ban(r["ip"], r["k"], cfg)
            state, note = ("active", "cf-edge blocked") if ok else ("failed", msg)
        con.execute("insert into bans(ts,ip,score,reasons,state,expires,note) "
                    "values(?,?,?,?,?,datetime('now',?),?)",
                    (now, r["ip"], r["s"], r["k"], state,
                     f"+{cfg['ban_hours']} hours", note))
        proposed += 1
    # --- /24 aggregation ------------------------------------------------
    # A per-IP threshold cannot see an attacker spread across a subnet: on
    # 2026-08-30 seven addresses in 94.154.43.0/24 each scored 3-6, all under
    # the per-IP threshold of 12, so nothing fired. Rolling them up to a /24
    # catches the shape. Deliberately stricter than the per-IP rule: it needs
    # BOTH a higher total AND several distinct addresses, because a /24 block
    # is a much blunter instrument than a single-IP block.
    subs = {}
    for r in con.execute(
            "select ip, sum(score) s, count(*) n from events "
            "where ip!='' and ip like '%.%.%.%' and ts > datetime('now',?) "
            "group by ip", (win,)):
        if is_allowlisted(r["ip"], cfg.get("allow", [])):
            continue
        net = ".".join(r["ip"].split(".")[:3]) + ".0/24"
        d = subs.setdefault(net, {"score": 0, "ips": set(), "events": 0})
        d["score"] += r["s"]; d["ips"].add(r["ip"]); d["events"] += r["n"]

    for net, d in sorted(subs.items(), key=lambda kv: -kv[1]["score"]):
        if d["score"] < cfg["subnet_threshold"] or len(d["ips"]) < cfg["subnet_min_ips"]:
            continue
        # ⚠️ Refuse a range that would take an allowlisted address with it.
        if net_overlaps_allow(net, cfg.get("allow", [])):
            continue
        if proposed >= cfg["max_bans_per_run"]:
            break
        if con.execute("select 1 from bans where ip=? and state in ('active','proposed') "
                       "and ts > datetime('now','-1 day')", (net,)).fetchone():
            continue
        reasons = f"subnet-spread: {len(d['ips'])} addresses, {d['events']} events"
        state, note = "proposed", "detect-only (enforce=false)"
        if cfg["enforce"]:
            ok, msg = cf_ban(net, reasons, cfg)
            state, note = ("active", "cf-edge blocked /24") if ok else ("failed", msg)
        con.execute("insert into bans(ts,ip,score,reasons,state,expires,note) "
                    "values(?,?,?,?,?,datetime('now',?),?)",
                    (now, net, d["score"], reasons, state,
                     f"+{cfg['ban_hours']} hours", note))
        proposed += 1
    con.commit()

    print(f"warden: {total_new} scored events, {proposed} ban(s) "
          f"{'ENFORCED' if cfg['enforce'] else 'proposed (detect-only)'}")
    con.close()

if __name__ == "__main__":
    sys.exit(main())
