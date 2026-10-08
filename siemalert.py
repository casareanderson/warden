#!/usr/bin/env python3
"""siemalert — the one place estate security findings turn into an alert post.

Reads the shared warden store and pushes anything new to the alert channel
(wlib.notify: Discord, a webhook, ntfy …).
Covers three producers:
  - netscan   (net_alerts)  — new device, IP change, IP conflict, new port
  - warden    (bans)        — scored ban proposals from the log side
  - crowdsec  (local alerts)— real detections against this estate

⚠️ WHY CROWDSEC IS FILTERED HARD HERE
`cscli metrics` shows tens of thousands of decisions, and almost none of them
are about you: they are CAPI community blocklists and third-party lists
(tor-exit-nodes, firehol), i.e. addresses CrowdSec blocks pre-emptively
because other people reported them. Alerting on those would produce a channel
that is 99.9% noise about strangers. Only alerts whose origin is THIS estate's
own engines are forwarded.

⚠️ SELF-REPORT SUPPRESSION
On 2026-09-21 the only local alert in seven days was `http-probing` from the
owner's own WAN address — a phone photo-backup client 404ing on deleted asset
thumbnails, eleven requests in four seconds. CrowdSec's own console flags this
class as "a security engine reported itself". An alerting tool that pages you
about your own phone is worse than no alerting tool, so anything matching the
configured self set is recorded and suppressed, not sent.

De-duplication is by content hash, not by row id, so a restart or a re-read
cannot replay an alert that was already delivered.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from wlib import config, notify  # noqa: E402

DB = Path(config.DB)
SELF_FILE = config.HOME / "self-ips.txt"


def crowdsec_argv(cmd):
    """Where `cscli` runs. warden.yml:
         sources: {crowdsec: {ssh: root@lapi-host}}              cscli on that host
         sources: {crowdsec: {ssh: me@nas, container: crowdsec}} cscli inside a container there
         sources: {crowdsec: {ssh: local}}                       cscli on this box
       CROWDSEC_HOST env (an address, reached as root) still works. None -> CrowdSec is skipped."""
    cs = config.get("sources.crowdsec") or {}
    ssh = cs.get("ssh") or (f"root@{os.environ['CROWDSEC_HOST']}" if os.environ.get("CROWDSEC_HOST") else "")
    if not ssh:
        return None
    if cs.get("container"):
        cmd = f"docker exec {cs['container']} {cmd}"
    if ssh == "local":
        return ["sh", "-c", cmd]
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10", ssh, cmd]
# How far back to ask CrowdSec for LOCAL alerts. Comfortably wider than the
# timer interval so a slow run or a restart cannot skip a window; the content
# hash stops the overlap becoming a duplicate post.
CROWDSEC_SINCE = "1h"
MAX_LINES = 12          # Discord caps at 2000 chars; keep a post readable.

SCHEMA = """
create table if not exists alert_sent(
  h text primary key, ts text, kind text, summary text);
create table if not exists alert_suppressed(
  id integer primary key, ts text, kind text, detail text, reason text);
"""

ICON = {
    "NEW_DEVICE": "🆕", "IP_CHANGE": "🔀", "IP_CONFLICT": "⚠️",
    "MAC_MULTI_IP": "🔗", "NEW_PORT": "🔓", "CRITICAL_MISSING": "🔴",
    "BAN": "🛡️", "CROWDSEC": "🚨",
}


def db():
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def load_self():
    """Addresses that are US. Anything reported against these is suppressed.

    Kept in a file rather than hardcoded because a home WAN address is usually
    dynamic — when it changes, this is the one place that needs editing, and
    a stale entry here causes missed alerts rather than a crash.
    """
    ips = set()
    try:
        for line in SELF_FILE.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                ips.add(line)
    except OSError:
        pass
    return ips


def already_sent(con, h):
    return con.execute("select 1 from alert_sent where h=?", (h,)).fetchone() is not None


def mark_sent(con, h, kind, summary):
    con.execute("insert or ignore into alert_sent(h,ts,kind,summary) values(?,?,?,?)",
                (h, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 kind, summary[:300]))


def suppress(con, kind, detail, reason):
    con.execute("insert into alert_suppressed(ts,kind,detail,reason) values(?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 kind, detail[:300], reason))


# ------------------------------------------------------------- producers --
def from_netscan(con, selfset):
    out = []
    rows = con.execute(
        "select * from net_alerts where notified=0 order by id").fetchall()
    for r in rows:
        line = f"{ICON.get(r['kind'],'•')} **{r['kind']}** `{r['ip']}` — {r['detail']}"
        h = hashlib.sha1(f"netscan\x00{r['kind']}\x00{r['mac']}\x00{r['detail']}"
                         .encode()).hexdigest()
        con.execute("update net_alerts set notified=1 where id=?", (r["id"],))
        if already_sent(con, h):
            continue
        out.append((h, r["kind"], line))
    return out


def from_warden(con, selfset):
    """New ban proposals from the log-scoring side."""
    out = []
    rows = con.execute(
        "select * from bans where ts > datetime('now','-1 day') order by id").fetchall()
    for r in rows:
        if r["ip"] in selfset:
            suppress(con, "BAN", f"{r['ip']} {r['reasons']}", "own address")
            continue
        h = hashlib.sha1(f"ban\x00{r['ip']}\x00{r['ts']}".encode()).hexdigest()
        if already_sent(con, h):
            continue
        state = r["state"]
        tag = "PROPOSED (detect-only)" if state == "proposed" else state.upper()
        out.append((h, "BAN",
                    f"{ICON['BAN']} **BAN {tag}** `{r['ip']}` score {r['score']} "
                    f"— {r['reasons']}"))
    return out


def from_crowdsec(con, selfset):
    """Local CrowdSec alerts only — never the CAPI/list decisions.

    `cscli alerts list` returns what THIS estate's engines detected. The huge
    numbers in `cscli metrics` are decisions imported from the community, which
    are not events that happened here and are not forwarded.
    """
    out = []
    argv = crowdsec_argv(f"cscli alerts list --since {CROWDSEC_SINCE} -o json")
    if argv is None:
        return out
    try:
        p = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=45)
        if p.returncode != 0:
            return out
        data = json.loads(p.stdout) if p.stdout.strip() not in ("", "null") else []
    except Exception as e:
        print(f"siemalert: crowdsec poll failed: {e}", file=sys.stderr)
        return out

    for a in data or []:
        src = a.get("source", {}) or {}
        ip = src.get("value") or src.get("ip") or "?"
        scenario = a.get("scenario", "?")
        # Skip anything imported rather than detected here.
        if str(a.get("machine_id", "")).lower() in ("", "capi") or "list" in scenario.lower():
            continue
        if ip in selfset:
            suppress(con, "CROWDSEC", f"{ip} {scenario}",
                     "self-report: source is our own address")
            continue
        h = hashlib.sha1(f"cs\x00{a.get('uuid') or ''}\x00{ip}\x00{scenario}"
                         .encode()).hexdigest()
        if already_sent(con, h):
            continue
        cc = src.get("cn", "")
        asn = src.get("as_name", "")
        out.append((h, "CROWDSEC",
                    f"{ICON['CROWDSEC']} **CrowdSec** `{ip}`"
                    f"{' [' + cc + ']' if cc else ''} — {scenario}"
                    f"{' (' + asn + ')' if asn else ''} "
                    f"×{a.get('events_count', '?')}"))
    return out


# ------------------------------------------------------------------ main --
def main():
    dry = "--dry-run" in sys.argv
    global CROWDSEC_SINCE
    for i, a in enumerate(sys.argv):
        if a == "--since" and i + 1 < len(sys.argv):
            CROWDSEC_SINCE = sys.argv[i + 1]
    con = db()
    selfset = load_self()

    items = []
    for fn in (from_netscan, from_warden, from_crowdsec):
        try:
            items.extend(fn(con, selfset))
        except Exception as e:
            print(f"siemalert: {fn.__name__} failed: {e}", file=sys.stderr)

    if not items:
        con.commit()
        con.close()
        print("siemalert: nothing new")
        return 0

    lines = [i[2] for i in items]
    body = "\n".join(lines[:MAX_LINES])
    if len(lines) > MAX_LINES:
        body += f"\n… and {len(lines) - MAX_LINES} more (see the warden dashboard)"
    header = f"**Estate security — {len(lines)} new finding(s)**"
    message = header + "\n" + body

    if dry:
        print(message)
        con.rollback()
        con.close()
        return 0

    ok = notify.send(message)

    # Only record delivery if it actually delivered. A failed send that marked
    # everything as sent would drop the alert permanently and silently — the
    # exact failure mode this whole subsystem exists to prevent.
    if ok:
        for h, kind, line in items:
            mark_sent(con, h, kind, line)
        con.commit()
        print(f"siemalert: sent {len(lines)} finding(s)")
    else:
        con.rollback()
        print("siemalert: send FAILED — nothing marked, will retry next run",
              file=sys.stderr)
        con.close()
        return 1
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
