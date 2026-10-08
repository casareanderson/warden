#!/usr/bin/env python3
"""edgeban.py — owner-approved edge blocklist for warden (built 2026-10-07).

  edgeban.py propose [--dry-run]   find candidates → one approval message each (✅/❌) on the alert channel
  edgeban.py poll                  apply the owner's reactions; expire old bans; push the rule if the set changed
  edgeban.py list                  show the ledger
  edgeban.py sync [--dry-run]      rebuild the Cloudflare rule from the active set (no messages)

ENFORCEMENT = ONE WAF custom rule, `warden: blocklist (owner-approved bans)`, expression
`(ip.src in {a b c/24 ...})`. Inline sets, so it needs only the WAF token (`cloudflare.token_secret`, default CF_API_TOKEN)
(a Cloudflare IP List would need Account Filter Lists:Edit, which a WAF token usually lacks).
Supersedes warden.py's cf_ban(), which posts to the IP Access Rules API Cloudflare is retiring.

Candidates:
  1. warden `bans` rows in state 'proposed' (its own log-side scoring, detect-only)
  2. edge repeat offenders: an IP — or its /24 when ≥2 addresses share it — that Cloudflare
     STOPPED (block/challenge) ≥2 times in 7 days AND that was seen on ≥2 distinct days
     (edge + log) within 120 days. One-off noise never qualifies.

Nothing is banned without the owner's ✅. Never: own IPs (self-ips.txt + warden.yml allow),
RFC1918, Cloudflare ranges — and a /24 is refused if it merely OVERLAPS any of those.
Bans expire after BAN_DAYS; ❌ is remembered for 90 days.
"""
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import warden  # noqa: E402   (load_conf, net_overlaps_allow, is_allowlisted — the vetted guards)
from geo import Geo  # noqa: E402
from wlib import config, secrets  # noqa: E402
from wlib import notify as td  # noqa: E402   (post / react / reactors / APPROVE / REJECT / owner)

DB = config.DB
CF = "https://api.cloudflare.com/client/v4"
CHANNEL = None                            # wlib.notify routes to notify.channel


def ZONE():  # noqa: N802
    return config.get("cloudflare.zone_id", "")


def OWNER():  # noqa: N802
    return td.owner()

DESC = "warden: blocklist (owner-approved bans)"
BAN_DAYS = 30
REJECT_DAYS = 90
PENDING_DAYS = 7
MAX_ENTRIES = 200                         # keeps the expression well under CF's 4 KB limit
MAX_NEW = 5
STOPPED = ("block", "managed_challenge", "challenge", "jschallenge", "drop", "connection_close")


def now():
    return datetime.now(timezone.utc)


def iso(t=None):
    return (t or now()).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists edge_bans(
        id integer primary key, target text, reason text, score integer, status text,
        message_id text, created text, decided text, expires text, note text);
      create index if not exists eb_target on edge_bans(target);
    """)
    return con


def allow_list():
    cfg = warden.load_conf()
    extra = list(cfg.get("allow", []))
    try:
        extra += [l.split("#")[0].strip() for l in open(config.HOME / "self-ips.txt") if l.split("#")[0].strip()]
    except OSError:
        pass
    return extra


def safe(target, extra):
    return not (warden.net_overlaps_allow(target, extra) if "/" in target else warden.is_allowlisted(target, extra))


def slash24(ip):
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else None


# ── candidates ───────────────────────────────────────────────────────────────
def candidates(con):
    extra = allow_list()
    out = {}
    for r in con.execute("select ip, score, reasons from bans where state='proposed' "
                         "and ts > datetime('now','-2 days')"):
        out[r["ip"]] = {"score": r["score"], "reason": f"warden log scoring: {r['reasons']}"}

    stopped = con.execute(
        f"select ip, ts, action, host, path from edge_events where ts > datetime('now','-7 days') "
        f"and action in ({','.join('?' * len(STOPPED))})", STOPPED).fetchall()
    groups = {}
    for r in stopped:
        if not safe(r["ip"], extra):
            continue
        groups.setdefault(slash24(r["ip"]) or r["ip"], []).append(r)
    for key, rows in groups.items():
        ips = sorted({r["ip"] for r in rows})
        target = key if (key.endswith("/24") and len(ips) >= 2) else ips[0] if len(ips) == 1 else key
        if len(rows) < 2:
            continue
        like = key[:-4] + "%" if key.endswith("/24") else key
        days = {d[0] for d in con.execute(
            "select distinct substr(ts,1,10) from edge_events where ip like ? and ts > datetime('now','-120 days') "
            "union select distinct substr(ts,1,10) from events where ip like ? and ts > datetime('now','-120 days')",
            (like, like))}
        if len(days) < 2:
            continue
        what = sorted({f"{r['host']}{r['path'][:30]}" for r in rows})[:3]
        out.setdefault(target, {"score": len(rows) * 5,
                                "reason": f"edge stopped {len(rows)}× from {len(ips)} address(es), seen on {len(days)} days "
                                          f"since {min(days)} — {', '.join(what)}"})
    return {t: c for t, c in out.items() if safe(t, extra)}


def msg_for(target, c, geo):
    cc = geo.cc(target.split("/")[0])
    return (f"🚫 **Edge ban proposal:** `{target}`{f' ({cc})' if cc else ''}\n{c['reason']}\n"
            f"✅ = block at Cloudflare for {BAN_DAYS} days · ❌ = no (not asked again for {REJECT_DAYS} days)")


def cmd_propose(dry):
    con = db()
    geo = Geo()
    posted = 0
    for target, c in sorted(candidates(con).items(), key=lambda kv: -kv[1]["score"]):
        prev = con.execute("select status, decided from edge_bans where target=? order by id desc limit 1",
                           (target,)).fetchone()
        if prev and (prev["status"] in ("pending", "active") or
                     (prev["status"] == "rejected" and prev["decided"] > iso(now() - timedelta(days=REJECT_DAYS)))):
            continue
        if posted >= MAX_NEW:
            print("more candidates held for the next run"); break
        m = msg_for(target, c, geo)
        if dry:
            print("DRY:", m.replace("\n", " | ")); posted += 1; continue
        mid = td.post(m, channel=CHANNEL)
        td.react(mid, td.APPROVE, channel=CHANNEL); td.react(mid, td.REJECT, channel=CHANNEL)
        con.execute("insert into edge_bans(target,reason,score,status,message_id,created) values(?,?,?,?,?,?)",
                    (target, c["reason"], c["score"], "pending", mid, iso()))
        con.commit(); posted += 1
        print(f"proposed {target}")
    if not posted:
        print("no new candidates")
    return 0


# ── the Cloudflare rule ──────────────────────────────────────────────────────
def cf(method, path, tok, body=None):
    r = requests.request(method, CF + path, headers={"Authorization": f"Bearer {tok}"}, json=body, timeout=30)
    d = r.json()
    if not d.get("success"):
        raise RuntimeError((d.get("errors") or [{"message": f"HTTP {r.status_code}"}])[0].get("message"))
    return d["result"]


def sync(con, dry=False):
    """Make the rule match the active set exactly. Returns a one-line summary."""
    tok = secrets.get(config.get("cloudflare.token_secret") or "CF_API_TOKEN")
    if not ZONE() or not tok:
        raise RuntimeError("cloudflare.zone_id / WAF token not configured")
    active = [r["target"] for r in con.execute("select target from edge_bans where status='active' order by id")]
    extra = allow_list()
    unsafe = [t for t in active if not safe(t, extra)]
    if unsafe:                                            # allowlist grew since approval → drop, loudly
        for t in unsafe:
            con.execute("update edge_bans set status='removed', note='now overlaps allowlist', decided=? "
                        "where target=? and status='active'", (iso(), t))
        con.commit()
        active = [t for t in active if t not in unsafe]
    active = active[-MAX_ENTRIES:]
    ep = cf("GET", f"/zones/{ZONE()}/rulesets/phases/http_request_firewall_custom/entrypoint", tok)
    rules = ep.get("rules", [])
    keep = [r for r in rules if (r.get("description") or "") != DESC]
    cur = next((r for r in rules if (r.get("description") or "") == DESC), None)
    expr = "(ip.src in {" + " ".join(active) + "})" if active else None
    if (cur and cur.get("expression") == expr) or (not cur and not expr):
        return f"rule already matches ({len(active)} entries)"
    if expr and not cur and len(keep) >= 5:
        raise RuntimeError("free plan allows 5 custom rules and all 5 are used")
    if dry:
        return f"DRY: would set {expr or 'NO rule (empty set)'}"
    new = [{"action": r["action"], "expression": r["expression"], "description": r.get("description", ""),
            "enabled": r.get("enabled", True)} for r in keep]
    if expr:
        new.append({"action": "block", "expression": expr, "description": DESC, "enabled": True})
    cf("PUT", f"/zones/{ZONE()}/rulesets/{ep['id']}", tok, {"rules": new})
    back = cf("GET", f"/zones/{ZONE()}/rulesets/phases/http_request_firewall_custom/entrypoint", tok)
    got = next((r.get("expression") for r in back.get("rules", []) if r.get("description") == DESC), None)
    if got != expr:
        raise RuntimeError(f"read-back mismatch: {got!r}")
    others = len([r for r in back.get("rules", []) if r.get("description") != DESC])
    if others != len(keep):
        raise RuntimeError(f"other rules changed: {len(keep)} → {others}")
    return f"rule now blocks {len(active)} entr{'y' if len(active) == 1 else 'ies'}"


def cmd_poll():
    con = db()
    changed = []
    for b in con.execute("select * from edge_bans where status='pending'").fetchall():
        yes = td.reactors(b["message_id"], td.APPROVE, channel=CHANNEL)
        if yes is None:
            con.execute("update edge_bans set status='expired', decided=?, note='message deleted' where id=?",
                        (iso(), b["id"])); continue
        no = td.reactors(b["message_id"], td.REJECT, channel=CHANNEL) or []
        if OWNER() in no:
            con.execute("update edge_bans set status='rejected', decided=? where id=?", (iso(), b["id"]))
            td.post(f"❌ `{b['target']}` left alone (not proposed again for {REJECT_DAYS} days).",
                    channel=CHANNEL, reply_to=b["message_id"])
        elif OWNER() in yes:
            con.execute("update edge_bans set status='active', decided=?, expires=? where id=?",
                        (iso(), iso(now() + timedelta(days=BAN_DAYS)), b["id"]))
            changed.append(("add", b))
        elif b["created"] < iso(now() - timedelta(days=PENDING_DAYS)):
            con.execute("update edge_bans set status='expired', decided=? where id=?", (iso(), b["id"]))
            td.post(f"⌛ `{b['target']}` proposal expired unanswered — nothing blocked.", channel=CHANNEL,
                    reply_to=b["message_id"])
    for b in con.execute("select * from edge_bans where status='active' and expires < ?", (iso(),)).fetchall():
        con.execute("update edge_bans set status='lapsed', note='ban period ended' where id=?", (b["id"],))
        changed.append(("lapse", b))
    con.commit()
    if not changed:
        return 0
    try:
        summary = sync(con)
    except Exception as e:  # noqa: BLE001
        for kind, b in changed:
            if kind == "add":   # not enforced → don't pretend it is
                con.execute("update edge_bans set status='failed', note=? where id=?", (str(e)[:200], b["id"]))
        con.commit()
        td.post(f"🛑 edge blocklist update FAILED: {str(e)[:200]} — nothing changed at Cloudflare.", channel=CHANNEL)
        return 1
    for kind, b in changed:
        if kind == "add":
            td.post(f"🚫 `{b['target']}` blocked at Cloudflare until {iso(now() + timedelta(days=BAN_DAYS))[:10]} — {summary}.",
                    channel=CHANNEL, reply_to=b["message_id"])
        else:
            td.post(f"🕊️ `{b['target']}` ban period ended, removed — {summary}.", channel=CHANNEL)
    print(summary)
    return 0


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else "list"
    if cmd == "propose":
        return cmd_propose("--dry-run" in a)
    if cmd == "poll":
        return cmd_poll()
    if cmd == "sync":
        print(sync(db(), "--dry-run" in a)); return 0
    for r in db().execute("select status, target, created, expires, reason from edge_bans order by id desc limit 50"):
        print(f"{r['status']:9} {r['target']:20} {r['created']}  exp {r['expires'] or '-':19}  {r['reason'][:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
