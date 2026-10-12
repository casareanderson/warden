#!/usr/bin/env python3
"""heartbeat.py — is every box up, and who last signed in to it? (owner 2026-10-11: "heartbeat, last login")

  heartbeat.py            heartbeat of every box (timer: every 5 min)
  heartbeat.py --logins   + SSH sign-ins from each box's own log (timer: every 15 min)
  heartbeat.py --list     print the current state

Heartbeat. One SSH call per Proxmox node answers for the node AND every container on it (`pvesh … /lxc` carries
each container's status and uptime), so a node with twenty containers costs one sign-in, not twenty. Plain hosts get
one `cat /proc/uptime`. A box that misses `heartbeat.down_after` beats in a row (default 3 = 15 min) is DOWN → one
message, and one more when it is back. Uptime going backwards between two beats = it rebooted (recorded; a message
only with `heartbeat.notify_reboot: true`, because approved patch runs reboot boxes too). A container that is
stopped on purpose is grey, not red; list it in `heartbeat.ignore` to drop it entirely. When a node does not answer,
its containers are UNKNOWN — never "down" — so one dead node is one message, not twenty-one.

Sign-ins. sshd's own lines (journald, or auth.log / secure / messages where there is no journal):
  Accepted <method> for <user> from <ip> … [<key type> <SHA256 fingerprint>]
  Failed password / Failed publickey / Invalid user
Logins made with a key that lives on THIS box (warden's own sweeps — and anything else that runs here with the same
key) are tagged `self` and kept out of "last login", or every box would always say "warden, 4 minutes ago".
`logins.known_keys: {SHA256:…: "backup job"}` names other automation keys the same way. Console logins (tty) come
from `last`. A `pct exec` / `lxc-attach` / web-console session writes no line at all, so warden also reads each
box's process table and records one still attached under init (ppid 1) on a tty as an `attach` sign-in — only while
it is still open. The first collection from a box is its baseline (silent); after that an accepted sign-in from a
user + address + key that box has never seen is NEW → a message (`logins.notify_new: false` turns that off).
Read-only on every box; nothing is installed.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
FIRST_DAYS = 30            # how far back the first collection from a box reads
OVERLAP_S = 3600           # later collections re-read this much before the newest stored sign-in (dedup by event)
KEEP_DAYS = 30
KEEP_SELF_DAYS = 2         # warden's own sign-ins are kept only as counts per pair after this

UPTIME = "cat /proc/uptime"
NODE_BEAT = "cat /proc/uptime; echo @@lxc; pvesh get /nodes/localhost/lxc --output-format json 2>/dev/null || echo '[]'"
DOCKER_BEAT = ("cat /proc/uptime; echo @@ctr; docker ps -aq 2>/dev/null | xargs -r docker inspect "
               "--format '{{.Name}}|{{.State.Status}}|{{.State.StartedAt}}' 2>/dev/null || true")
LOGINS = r'''export LC_ALL=C
S=${SINCE:-2592000}
# keep EVERY sign-in that isn't ours, but only the newest 200 made with this box's own keys ($SELF) — on a box
# warden sweeps every few minutes its own lines would otherwise push a person's sign-in out of any line cap
cap() { if [ -n "$SELF" ]; then awk -v s="$SELF" 'BEGIN{n=split(s,a," ")}
    {m=0; for(i=1;i<=n;i++) if(index($0,a[i])){m=1;break}}
    m{k++; o[k]=$0; delete o[k-200]} !m{print}
    END{for(i=k-199;i<=k;i++) if(i in o) print o[i]}' | tail -n 20000; else tail -n 20000; fi; }
out=""
if command -v journalctl >/dev/null 2>&1; then
  out=$(journalctl -q --no-pager -o short-unix -t sshd -t sshd-session --since "@$(( $(date +%s) - S ))" 2>/dev/null \
        | grep -E 'Accepted |Failed (password|publickey)|Invalid user' | cap)
fi
if [ -n "$out" ]; then printf '%s\n' "$out"; else
  for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [ -r "$f" ] && grep -hE 'sshd.*(Accepted |Failed (password|publickey)|Invalid user)' "$f" | cap && break
  done
fi
echo @@last
(last -w --time-format iso -n 30 2>/dev/null || wtmpdb last -n 30 2>/dev/null) | grep -E '^[^ ]+ +(tty|console)' | head -30
echo @@ps
ps -eo pid=,ppid=,tty=,user=,comm= 2>/dev/null
true
'''
# one node session covers its own sign-ins and every running container's
NODE_LOGINS = (r'''SINCE=@SINCE@; SELF='@SELF@'; export SINCE SELF
sh -c "$L"
for id in $(pct list 2>/dev/null | awk 'NR>1 && $2=="running" {print $1}'); do
  echo "@@ct:$id"; pct exec "$id" -- env SINCE="$SINCE" SELF="$SELF" sh -c "$L" 2>/dev/null
done
''')

ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+(?: \w+)?(?::\s*(\S+) (SHA256:\S+))?")
FAILED = re.compile(r"Failed (password|publickey) for (?:(invalid user) )?(\S*) from (\S+)")
INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s")
ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?)\s")
LAST = re.compile(r"^(\S+)\s+(tty\S*|console)\s+(?:(\S+)\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\S*)")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists hb(target text primary key, name text, kind text, node text, state text,
        last_ok text, last_try text, misses integer default 0, rtt_ms integer, uptime_s integer, note text,
        alerted integer default 0, down_since text);
      create table if not exists hb_events(id integer primary key, ts text, target text, event text, detail text);
      create table if not exists logins(id integer primary key, target text, ts text, user text, src text,
        method text, key_fp text, ok integer, self integer default 0, new integer default 0,
        unique(target, ts, user, src, ok, method));
      create index if not exists logins_t on logins(target, ts);
      create table if not exists login_pairs(target text, user text, src text, key_fp text, ok integer,
        first_ts text, last_ts text, n integer, self integer default 0, primary key(target, user, src, key_fp, ok));
      create table if not exists login_runs(target text primary key, ts text, status text, note text);
    """)
    return con


# ── who is "us" ──────────────────────────────────────────────────────────────
def own_keys():
    """Fingerprints of the SSH keys this box signs in with (warden's own sweeps) + logins.known_keys."""
    keys = {}
    for p in sorted(Path(os.path.expanduser("~/.ssh")).glob("*.pub")):
        try:
            out = subprocess.run(["ssh-keygen", "-lf", str(p)], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        f = out.split()
        if len(f) >= 2 and f[1].startswith("SHA256:"):
            keys[f[1]] = f"this box ({p.stem})"
    for fp, label in (config.get("logins.known_keys") or {}).items():
        keys[str(fp)] = str(label)
    return keys


# ── parsing ──────────────────────────────────────────────────────────────────
def _ts(line, year):
    """(utc 'YYYY-mm-dd HH:MM:SS', rest of line) from short-unix, ISO or classic syslog lines."""
    head, _, rest = line.partition(" ")
    try:
        return utc(float(head)), rest
    except ValueError:
        pass
    m = ISO_TS.match(line)
    if m:
        s = m.group(1)
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
        t = t if t.tzinfo else t.astimezone()            # naive = the box's local time; assume ours
        return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), line[m.end():]
    m = SYSLOG_TS.match(line)
    if m:
        t = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S").astimezone()
        if t > datetime.now().astimezone():                # "Dec 31" read in January
            t = t.replace(year=year - 1)
        return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), line[m.end():]
    return None, line


def parse(text, keys, now_ts=None):
    """sshd + `last` lines → sign-in events (dicts). Unparseable lines are skipped, never guessed.

    `@@ps` adds the box's own process table. `pct exec`, `lxc-attach` and the Proxmox web console write no log line,
    so a session started that way is caught here only while it is still open: a shell still attached directly under
    the container's init (ppid 1) on a real tty. warden's own sweep runs `sh -c` with no tty, so it never matches."""
    year, out, section = datetime.now().year, [], "ssh"
    for line in (text or "").splitlines():
        line = line.rstrip()
        if line == "@@last":
            section = "last"; continue
        if line == "@@ps":
            section = "ps"; continue
        if section == "ps":
            f = line.split(None, 4)
            if len(f) >= 5 and f[0].isdigit() and f[1] == "1" and f[2] not in ("?", "??") \
                    and f[4] not in ("getty", "agetty", "login"):
                out.append(dict(ts=now_ts or now(), user=f[3], src=f[2], method="attach",
                                key_fp=f"pid:{f[0]}", ok=1, self=0))
            continue
        if section == "last":
            m = LAST.match(line)
            if m:
                ts, _ = _ts(m.group(4) + " ", year)
                if ts:
                    out.append(dict(ts=ts, user=m.group(1), src=m.group(3) or m.group(2), method="console",
                                    key_fp="", ok=1, self=0))
            continue
        ts, rest = _ts(line, year)
        if not ts:
            continue
        m = ACCEPT.search(rest)
        if m:
            fp = m.group(5) or ""
            out.append(dict(ts=ts, user=m.group(2), src=m.group(3), method=m.group(1), key_fp=fp, ok=1,
                            self=1 if fp and fp in keys and keys[fp].startswith("this box") else 0,
                            label=keys.get(fp, "")))
            continue
        m = FAILED.search(rest)
        if m:
            out.append(dict(ts=ts, user=m.group(3) or "?", src=m.group(4), method=m.group(1), key_fp="", ok=0, self=0,
                            invalid=bool(m.group(2))))
            continue
        m = INVALID.search(rest)
        if m and "Failed" not in rest:
            out.append(dict(ts=ts, user=m.group(1) or "?", src=m.group(2), method="invalid-user", key_fp="", ok=0, self=0))
    # sshd logs "Invalid user X" AND "Failed password for invalid user X" for one password attempt: count it once
    failed = {(e["user"], e["src"], e["ts"][:16]) for e in out if e.get("invalid")}
    return [e for e in out if not (e["method"] == "invalid-user" and (e["user"], e["src"], e["ts"][:16]) in failed)]


def split_sections(text):
    """A node's batched output → {target: text}. The node's own lines come first, then '@@ct:<vmid>' blocks."""
    parts, cur, buf = {}, None, []
    for line in (text or "").splitlines():
        if line.startswith("@@ct:"):
            parts[cur] = "\n".join(buf); cur, buf = "ct:" + line[5:].strip(), []
        else:
            buf.append(line)
    parts[cur] = "\n".join(buf)
    return parts


# ── heartbeat ────────────────────────────────────────────────────────────────
def beat_targets():
    """Nodes, plain hosts and the local box — plus docker-capable boxes, whose containers are answered for by the box."""
    ts = [t for t in hosts.targets(discover=False) if t["kind"] in ("node", "host", "local")]
    for h in hosts.declared():
        kind, ssh = h.get("kind", "linux"), h.get("ssh", "")
        if kind != "docker" and not h.get("docker"):
            continue
        ip = ssh.split("@", 1)[-1] if ssh else "local"
        tid = f"host:{ip}"
        box = next((t for t in ts if t["target"] == tid), None)
        if box is not None:              # a linux/local box that already heartbeats: also report its docker containers
            box["docker"] = True
            box["node"] = ip
        else:                            # a pure docker box (kind: docker) has no host target yet
            ts.append({"target": tid, "kind": "host", "name": h.get("name") or ip, "node": ip, "ssh": ssh,
                       "docker": True, "local": not ssh})
    return ts


def login_targets():
    """Boxes whose own sign-ins are read (a node's session reads all its containers inside _collect)."""
    return [t for t in hosts.targets(discover=False) if t["kind"] in ("node", "host", "local")]


def _beat(t):
    t0 = time.time()
    cmd = NODE_BEAT if t["kind"] == "node" else DOCKER_BEAT if t.get("docker") else UPTIME
    try:
        rc, out, err = hosts.remote(t, cmd, timeout=25)
    except Exception as e:  # noqa: BLE001
        rc, out, err = -1, "", str(e)
    return t, rc, out or "", (err or "").strip()[:160], int((time.time() - t0) * 1000)


def _containers(t, out):
    """A box's batched output → container rows (target, name, kind, running, uptime)."""
    if t.get("docker"):
        return _docker_containers(t, out)
    cts = []
    try:
        raw = json.loads(out.split("@@lxc", 1)[1])
    except (IndexError, ValueError):
        return cts
    for c in raw:
        running = c.get("status") == "running"
        cts.append({"target": f"ct:{c.get('vmid')}", "name": c.get("name") or f"ct:{c.get('vmid')}", "kind": "ct",
                    "running": running, "uptime": int(c.get("uptime") or 0) if running else None})
    return cts


def _docker_containers(t, out):
    """`docker inspect` lines (`/name|status|startedAt`) → container rows; uptime from StartedAt, not CreatedAt."""
    cts = []
    try:
        body = out.split("@@ctr", 1)[1]
    except IndexError:
        return cts
    for line in body.splitlines():
        name, sep, rest = line.partition("|")
        if not sep:
            continue
        status, sep2, started = rest.partition("|")
        name = name.lstrip("/").strip()
        if not name:
            continue
        running = status.strip() == "running"
        up = None
        if running and sep2:
            try:
                # docker prints RFC3339Nano (9 fractional digits); fromisoformat wants at most 6
                iso = re.sub(r"\.(\d{6})\d+", r".\1", started.strip().replace("Z", "+00:00"))
                st = datetime.fromisoformat(iso)
                up = int(time.time() - st.timestamp())
            except ValueError:
                up = None
        cts.append({"target": f"ctr:{t['node']}:{name}", "name": name, "kind": "ctr",
                    "running": running, "uptime": up})
    return cts


def beat(con=None):
    con = con or db()
    ignore = set(config.get("heartbeat.ignore") or [])
    seen = []
    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(_beat, beat_targets()))
    ts = now()
    for t, rc, out, err, ms in results:
        up_s = None
        head = out.split("@@", 1)[0].split()
        if rc == 0 and head:
            try:
                up_s = int(float(head[0]))
            except ValueError:
                up_s = None
        ok = rc == 0 and up_s is not None
        record(con, t["target"], t["name"], t["kind"], t.get("node"), "up" if ok else "down", ts, ms if ok else None,
               up_s, "" if ok else (err or f"exit {rc}"))
        seen.append(t["target"])
        if t.get("node") is None:          # a plain host/local: no containers under it
            continue
        if not ok:          # can't see inside a box that doesn't answer: its containers are unknown, not down
            for r in con.execute("select target from hb where node=? and kind in ('ct','ctr')", (t["node"],)).fetchall():
                con.execute("update hb set state='unknown', last_try=?, note=? where target=?",
                            (ts, f"node {t['name']} not answering", r["target"]))
                seen.append(r["target"])
            continue
        for c in _containers(t, out):
            if c["target"] in ignore:
                continue
            record(con, c["target"], c["name"], c["kind"], t["node"], "up" if c["running"] else "stopped", ts,
                   None, c["uptime"] if c["running"] else None, "" if c["running"] else "stopped")
            seen.append(c["target"])
    # a container that vanished from its box's list (destroyed / migrated) stops being tracked
    for r in con.execute("select target from hb where kind in ('ct','ctr')").fetchall():
        if r["target"] not in seen and not con.execute(
                "select 1 from hb h join hb n on n.node=h.node and n.kind in ('node','host','local') "
                "where h.target=? and n.state!='up'", (r["target"],)).fetchone():
            con.execute("delete from hb where target=?", (r["target"],))
            con.execute("insert into hb_events(ts,target,event,detail) values(?,?,?,?)",
                        (ts, r["target"], "gone", "no longer listed on its node"))
    con.execute("delete from hb_events where ts < datetime('now', ?)", (f"-{KEEP_DAYS} days",))
    con.commit()                       # commit BEFORE any notify call (patcher reply-loop lesson)
    alerts(con)
    return 0


def record(con, target, name, kind, node, state, ts, rtt, up_s, note):
    prev = con.execute("select * from hb where target=?", (target,)).fetchone()
    if prev and state == "up" and up_s is not None and prev["uptime_s"] is not None and prev["state"] == "up" \
            and up_s + 60 < prev["uptime_s"]:
        con.execute("insert into hb_events(ts,target,event,detail) values(?,?,?,?)",
                    (ts, target, "rebooted", f"up {fmt_dur(up_s)} (was {fmt_dur(prev['uptime_s'])})"))
    misses = 0 if state != "down" else (prev["misses"] + 1 if prev else 1)
    con.execute("""insert into hb(target,name,kind,node,state,last_ok,last_try,misses,rtt_ms,uptime_s,note)
                   values(?,?,?,?,?,?,?,?,?,?,?) on conflict(target) do update set name=excluded.name, kind=excluded.kind,
                   node=excluded.node, state=excluded.state, last_ok=coalesce(excluded.last_ok, hb.last_ok),
                   last_try=excluded.last_try, misses=excluded.misses, rtt_ms=coalesce(excluded.rtt_ms, hb.rtt_ms),
                   uptime_s=coalesce(excluded.uptime_s, hb.uptime_s), note=excluded.note""",
                (target, name, kind, node, state, ts if state == "up" else None, ts, misses, rtt, up_s, note))


def fmt_dur(s):
    s = int(s or 0)
    return f"{s // 86400}d {s % 86400 // 3600}h" if s >= 86400 else f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 \
        else f"{s // 60}m"


def alerts(con):
    need = int(config.get("heartbeat.down_after") or 3)
    for r in con.execute("select * from hb").fetchall():
        bad = r["state"] == "down" and r["misses"] >= need or r["state"] == "stopped"
        if bad and not r["alerted"]:
            if r["state"] == "stopped" and r["last_ok"] is None:
                continue            # was never seen running: stopped on purpose, nothing to say
            con.execute("update hb set alerted=1, down_since=? where target=?", (r["last_try"], r["target"]))
            con.execute("insert into hb_events(ts,target,event,detail) values(?,?,?,?)",
                        (r["last_try"], r["target"], "down" if r["state"] == "down" else "stopped", r["note"] or ""))
            con.commit()
            last = f"last answered {r['last_ok']} UTC" if r["last_ok"] else "never answered"
            what = "is not answering" if r["state"] == "down" else "has STOPPED"
            send(f"💔 **{r['name']}** (`{r['target']}`) {what} — {last}. {(r['note'] or '')[:120]}".strip())
        elif r["alerted"] and r["state"] == "up":
            since = r["down_since"]
            mins = round((datetime.now(timezone.utc) - datetime.strptime(since, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)).total_seconds() / 60) if since else None
            rebooted = r["uptime_s"] is not None and mins is not None and r["uptime_s"] < (mins + 15) * 60
            con.execute("update hb set alerted=0, down_since=null where target=?", (r["target"],))
            con.execute("insert into hb_events(ts,target,event,detail) values(?,?,?,?)",
                        (r["last_try"], r["target"], "back", f"after ~{mins} min" if mins is not None else ""))
            con.commit()
            send(f"💚 **{r['name']}** (`{r['target']}`) is back" + (f" after about {mins} min" if mins is not None else "")
                 + (f" — it rebooted (up {fmt_dur(r['uptime_s'])})" if rebooted else "") + ".")
    if config.get("heartbeat.notify_reboot"):
        for e in con.execute("select * from hb_events where event='rebooted' and detail not like '%·sent' "
                             "and ts > datetime('now','-1 hour')").fetchall():
            con.execute("update hb_events set detail=detail || ' ·sent' where id=?", (e["id"],)); con.commit()
            send(f"🔁 `{e['target']}` rebooted — {e['detail']}.")


def send(text):
    try:
        notify.send(text)
    except Exception as e:  # noqa: BLE001
        print(f"notify: {e}")
    print(text)


# ── sign-ins ─────────────────────────────────────────────────────────────────
def since_for(con, target):
    r = con.execute("select max(ts) m from logins where target=?", (target,)).fetchone()
    if not r or not r["m"]:
        return FIRST_DAYS * 86400
    newest = datetime.strptime(r["m"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return int(max(time.time() - newest + OVERLAP_S, OVERLAP_S))


def _collect(args):
    t, since, mine = args
    mine = " ".join(k for k in mine if re.fullmatch(r"SHA256:[A-Za-z0-9+/=]+", k))     # safe inside '…'
    try:
        if t["kind"] == "node":
            script = f"L={hosts.sh_quote(LOGINS)}\n" + NODE_LOGINS.replace("@SINCE@", str(since)).replace("@SELF@", mine)
            rc, out, err = hosts.remote(t, script, timeout=240)
        else:
            rc, out, err = hosts.remote(t, f"SINCE={since}\nSELF='{mine}'\n" + LOGINS, timeout=240, root=True)
    except Exception as e:  # noqa: BLE001
        rc, out, err = -1, "", str(e)
    return t, rc, out or "", (err or "").strip()[:160]


def logins(con=None):
    con = con or db()
    keys = own_keys()
    ts = now()
    jobs = []
    for t in login_targets():
        # a node's session reads all its containers: give it the widest window any of them needs
        tids = [t["target"]] + ([r["target"] for r in con.execute("select target from hb where node=? and kind='ct'",
                                                                    (t["node"],))] if t["kind"] == "node" else [])
        jobs.append((t, max(since_for(con, x) for x in tids), [k for k, v in keys.items() if v.startswith("this box")]))
    with ThreadPoolExecutor(6) as ex:
        results = list(ex.map(_collect, jobs))
    new_lines = []
    for t, rc, out, err in results:
        parts = split_sections(out) if t["kind"] == "node" else {None: out}
        for key, text in parts.items():
            target = t["target"] if key is None else key
            if rc != 0 and not text.strip():
                con.execute("insert into login_runs values(?,?,?,?) on conflict(target) do update set ts=excluded.ts, "
                            "status=excluded.status, note=excluded.note", (target, ts, "error", err or f"exit {rc}"))
                continue
            new_lines += store(con, target, parse(text, keys, ts), ts)
    con.execute("delete from logins where ts < datetime('now', ?)", (f"-{KEEP_DAYS} days",))
    con.execute("delete from logins where self=1 and ts < datetime('now', ?)", (f"-{KEEP_SELF_DAYS} days",))
    con.commit()                       # commit BEFORE any notify call
    if new_lines and config.get("logins.notify_new", True):
        names = {r["target"]: r["name"] for r in con.execute("select target, name from hb")}
        body = "\n".join(f"• **{names.get(tg, tg)}** (`{tg}`): {u} from {s} via {m} at {tsx} UTC"
                         for tg, u, s, m, tsx in new_lines[:10])
        more = f"\n… +{len(new_lines) - 10} more → warden · Endpoints" if len(new_lines) > 10 else ""
        send(f"🔑 **New sign-in** — a user, address and key these boxes haven't seen before:\n{body}{more}\n"
             "If that wasn't you or one of your jobs, look now.")
    return 0


def store(con, target, events, ts):
    """Insert events (dedup by event), maintain per-pair counts; return NEW accepted pairs (after the baseline)."""
    baseline = not con.execute("select 1 from login_runs where target=? and status='ok'", (target,)).fetchone()
    fresh = []
    for e in sorted(events, key=lambda x: x["ts"]):
        if e.get("method") == "attach":
            # a still-open pct exec / lxc-attach / web-console session: dedup by its pid, not its collection time,
            # so the same session seen on two sweeps is one sign-in, not a new row each 15 minutes.
            pk = (target, e["user"], e["src"], e["key_fp"], e["ok"])
            had = con.execute("select 1 from login_pairs where target=? and user=? and src=? and key_fp=? and ok=?",
                              pk).fetchone()
            if had:
                con.execute("update login_pairs set last_ts=max(login_pairs.last_ts, ?) where target=? and user=? "
                            "and src=? and key_fp=? and ok=?", (e["ts"],) + pk)
                continue
            con.execute("insert or ignore into logins(target,ts,user,src,method,key_fp,ok,self) values(?,?,?,?,?,?,?,?)",
                        (target, e["ts"], e["user"], e["src"], e["method"], e["key_fp"], e["ok"], e["self"]))
            con.execute("insert into login_pairs values(?,?,?,?,?,?,?,1,?) on conflict(target,user,src,key_fp,ok) do update "
                        "set last_ts=max(login_pairs.last_ts, excluded.last_ts), n=login_pairs.n+1",
                        pk + (e["ts"], e["ts"], e["self"]))
            continue
        cur = con.execute("insert or ignore into logins(target,ts,user,src,method,key_fp,ok,self) values(?,?,?,?,?,?,?,?)",
                          (target, e["ts"], e["user"], e["src"], e["method"], e["key_fp"], e["ok"], e["self"]))
        if cur.rowcount != 1:
            continue
        pk = (target, e["user"], e["src"], e["key_fp"], e["ok"])
        had = con.execute("select 1 from login_pairs where target=? and user=? and src=? and key_fp=? and ok=?",
                          pk).fetchone()
        con.execute("insert into login_pairs values(?,?,?,?,?,?,?,1,?) on conflict(target,user,src,key_fp,ok) do update "
                    "set last_ts=max(login_pairs.last_ts, excluded.last_ts), n=login_pairs.n+1",
                    pk + (e["ts"], e["ts"], e["self"]))
        if not had and not baseline and e["ok"] and not e["self"] and e["method"] != "console":
            con.execute("update logins set new=1 where id=?", (cur.lastrowid,))
            fresh.append((target, e["user"], e["src"], e["method"], e["ts"]))
    con.execute("insert into login_runs values(?,?,?,?) on conflict(target) do update set ts=excluded.ts, "
                "status='ok', note=excluded.note", (target, ts, "ok", f"{len(events)} line(s) read"))
    return fresh


def summary(con):
    """Per box: heartbeat + last non-self sign-in + 24-h counts (what the console and the API show)."""
    rows = []
    for r in con.execute("select * from hb order by kind != 'node', node, target").fetchall():
        last = con.execute("select ts,user,src,method,key_fp,new from logins where target=? and ok=1 and self=0 "
                           "order by ts desc limit 1", (r["target"],)).fetchone()
        if not last:   # older than the raw window: fall back to the pair table
            last = con.execute("select last_ts ts,user,src,'' method,key_fp,0 new from login_pairs where target=? and "
                               "ok=1 and self=0 order by last_ts desc limit 1", (r["target"],)).fetchone()
        n = con.execute("select sum(ok=1 and self=0) h, sum(ok=1 and self=1) s, sum(ok=0) f from logins where target=? "
                        "and ts > datetime('now','-24 hours')", (r["target"],)).fetchone()
        run = con.execute("select ts, status, note from login_runs where target=?", (r["target"],)).fetchone()
        rows.append(dict(r, last_login=dict(last) if last else None, logins_24h=n["h"] or 0, self_24h=n["s"] or 0,
                         failed_24h=n["f"] or 0, login_run=dict(run) if run else None))
    return rows


def main():
    a = sys.argv[1:]
    con = db()
    if "--list" in a:
        for r in summary(con):
            ll = r["last_login"]
            print(f"{r['target']:<20} {r['state']:<8} up {fmt_dur(r['uptime_s']) if r['uptime_s'] else '—':<8} "
                  f"last ok {r['last_ok'] or '—':<20} login {ll['user'] + '@' + ll['src'] + ' ' + ll['ts'] if ll else '—'}"
                  f"  24h: {r['logins_24h']} in / {r['failed_24h']} failed / {r['self_24h']} warden")
        return 0
    beat(con)
    if "--logins" in a:
        logins(con)
    return 0


if __name__ == "__main__":
    sys.exit(main())
