#!/usr/bin/env python3
"""devicewatch.py — step 3: decide what a device's NEW behaviour means (owner 2026-10-10: "smart decisions on detection").

Input: wlib/behaviour.py baselines. When a FIXED-FUNCTION device (bulb, plug, TV, speaker, camera, printer, IoT, hub,
network kit) that is past its learning window looks up a domain it has never used, warden gathers the facts and
scores them. Phones and laptops are never scored here: new domains are what they do all day.

Facts (all from warden's own tables, no model): what the device is, what it usually talks to, how many OTHER devices
in the house already use this domain, whether devices of the same kind picked it up at the same time (a fleet-wide
firmware or cloud change), the hour, the TLD, whether the domain carries the maker's name.

Decision ladder:
  < 25   learned       quietly added to the baseline (still listed in the console)
  25-54  logged        shown in the console, no message
  ≥ 55   review        a Discord card: the facts, a plain-English read from the Hermes `sec` agent, and
                       ✅ = normal, learn it · ❌ = suspicious. The owner's answer is recorded and never asked again.
The Hermes text is advisory and labelled as such; the score and the facts never come from it. Threat-feed matches
are alerted separately by netintel.py and are not re-scored here.

  devicewatch.py            score new behaviour since the last run, post reviews, apply decisions (timer: 10 min)
  devicewatch.py --dry      score the whole baseline history without writing or posting (to tune thresholds)
"""
import json
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wlib import behaviour, config, notify  # noqa: E402

LOG_AT, REVIEW_AT = 25, 55
# A "fixed-function" device whose own baseline already spans this many domains is really a forwarder or a little
# computer (measured 2026-10-10: a streaming-DNS box at 73, the next busiest gadget 27, bulbs/cameras 1-6). New
# domains are routine for it, so it is treated like a phone and not scored.
BUSY_DOMAINS = 40
RISKY_TLD = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "click", "work", "icu", "cyou", "buzz", "rest", "zip",
             "mov", "ru", "su", "cn"}
TZ = ZoneInfo(config.get("estate.timezone") or "Europe/London")


def db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.row_factory = sqlite3.Row
    behaviour.schema(con)
    con.executescript("""
      create table if not exists dev_findings(id integer primary key, ts text, identity text, domain text, score integer,
        decision text, reasons text, facts text, explain text, message_id text, verdict text, decided_at text,
        unique(identity, domain));
      create table if not exists watermarks(source text primary key, pos text);""")
    return con


def device_row(con, ident):
    r = con.execute("select name, kind, fixed, room, maker from devices where identity=? order by last_seen desc limit 1",
                    (ident,)).fetchone()
    return dict(r) if r else None


def facts(con, ident, dom, first_seen, dev):
    others = con.execute("select count(distinct identity) from dev_dns where domain=? and identity!=?", (dom, ident)).fetchone()[0]
    fleet = con.execute("""select count(distinct d.identity) from dev_dns d join devices v on v.identity=d.identity
                           where d.domain=? and d.identity!=? and v.kind=? and abs(julianday(d.first_seen)-julianday(?)) < 1""",
                        (dom, ident, dev["kind"], first_seen)).fetchone()[0]
    usual = [r[0] for r in con.execute("select domain from dev_dns where identity=? and domain!=? order by days desc, hits desc "
                                       "limit 6", (ident, dom))]
    t = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(TZ)
    maker_words = [w for w in re.findall(r"[a-z]{3,}", (dev.get("maker") or "").lower()) if w not in {"company", "limited",
                   "technology", "technologies", "electronics", "connected", "lighting", "shenzhen", "hangzhou", "co"}]
    return {"device": dev["name"], "kind": dev["kind"], "room": dev.get("room") or "", "domain": dom,
            "first_seen_local": t.strftime("%a %d %b %H:%M"), "hour": t.hour, "other_devices_using_it": others,
            "same_kind_same_day": fleet, "usual_domains": usual, "tld": dom.rsplit(".", 1)[-1],
            "maker_in_domain": any(w in dom for w in maker_words)}


def score(f):
    s, why = 40, ["new domain for a fixed-function device"]
    if f["other_devices_using_it"] == 0:
        s += 25; why.append("no other device in the house uses it")
    elif f["other_devices_using_it"] >= 2:
        s -= 25; why.append(f"{f['other_devices_using_it']} other devices already use it")
    if f["same_kind_same_day"] >= 2:
        s -= 30; why.append(f"{f['same_kind_same_day']} other {f['kind']}s picked it up the same day (fleet change)")
    if f["maker_in_domain"]:
        s -= 20; why.append("domain carries the maker's name")
    if f["hour"] < 5:
        s += 15; why.append("first seen between midnight and 5am")
    if f["tld"] in RISKY_TLD:
        s += 15; why.append(f".{f['tld']} is a high-abuse TLD")
    return max(0, min(100, s)), why


def decision(s):
    return "review" if s >= REVIEW_AT else "logged" if s >= LOG_AT else "learned"


def explain(f):
    """The Hermes `sec` agent's plain-English read. Advisory only; '' if unavailable."""
    prompt = ("You are helping a homeowner review their network. A device looked up a domain it has never used before. "
              "Using ONLY these facts (add none), write at most two short sentences: what it COULD be (give the innocent "
              "and the worrying explanation if both fit) and one concrete thing to check. Be measured: never say "
              "'almost certainly', 'compromised' or 'replace it'; the owner decides. Do not repeat the facts. "
              "Facts: " + json.dumps(f))
    try:
        p = subprocess.run(["/usr/local/bin/hermes", "--profile", config.get("devicewatch.hermes_profile") or "sec", "-z",
                            prompt], capture_output=True, text=True, timeout=180, cwd="/root")
        out = re.sub(r"\s+", " ", (p.stdout or "").replace("**", "")).strip()
        sents = re.split(r"(?<=[.!?])\s+", out)
        txt = " ".join(sents[:2])
        txt = txt if len(txt) <= 450 else txt[:450].rsplit(" ", 1)[0] + "…"
        return txt if p.returncode == 0 and out else ""     # 10-10: it ran to three sentences and was alarmist
    except Exception:  # noqa: BLE001
        return ""


def card(f, s, why, read):
    usual = ", ".join(f"`{d}`" for d in f["usual_domains"][:4]) or "nothing else yet"
    return (f"🔍 **New behaviour: {f['device']}** ({f['kind']}{', ' + f['room'] if f['room'] else ''}) looked up "
            f"`{f['domain']}` for the first time · {f['first_seen_local']}\n"
            f"Score **{s}**: {'; '.join(why)}.\nUsually talks to: {usual}\n"
            + (f"Hermes (advisory): {read}\n" if read else "")
            + "✅ = normal, learn it · ❌ = suspicious, keep an eye on it")


def candidates(con, since):
    """New (device, domain) pairs first seen after `since`, for devices past their learning window at that moment."""
    return con.execute("""select d.identity, d.domain, d.first_seen from dev_dns d join dev_obs o on o.identity=d.identity
                          where d.first_seen > ? and julianday(d.first_seen) - julianday(o.first_obs) >= ?
                          order by d.first_seen""", (since, behaviour.LEARN_DAYS)).fetchall()


def run(dry=False):
    con = db()
    wm = con.execute("select pos from watermarks where source='devicewatch'").fetchone()
    since = "0000" if dry else (wm[0] if wm else time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 3600)))
    counts, newest, reviews = {"learned": 0, "logged": 0, "review": 0, "skipped": 0}, since, []
    for c in candidates(con, since):
        newest = max(newest, c["first_seen"])
        dev = device_row(con, c["identity"])
        if not dev or not dev["fixed"]:
            counts["skipped"] += 1; continue
        if con.execute("select count(*) from dev_dns where identity=?", (c["identity"],)).fetchone()[0] > BUSY_DOMAINS:
            counts["skipped"] += 1; continue                  # busy device: see BUSY_DOMAINS
        if con.execute("select 1 from dev_findings where identity=? and domain=?", (c["identity"], c["domain"])).fetchone():
            continue
        f = facts(con, c["identity"], c["domain"], c["first_seen"], dev)
        s, why = score(f); d = decision(s); counts[d] += 1
        if dry:
            if d != "learned":
                print(f"{d:<7} {s:>3}  {f['device'][:26]:<26} {f['kind']:<8} {f['domain']:<28} {'; '.join(why[1:])}")
            continue
        con.execute("insert into dev_findings(ts, identity, domain, score, decision, reasons, facts) values(?,?,?,?,?,?,?)",
                    (c["first_seen"], c["identity"], c["domain"], s, d, json.dumps(why), json.dumps(f)))
        if d == "review":
            reviews.append((con.execute("select last_insert_rowid()").fetchone()[0], f, s, why))
    if not dry:
        con.execute("insert or replace into watermarks(source, pos) values('devicewatch', ?)", (newest,))
        con.commit()                                  # commit BEFORE any notify call (the patcher reply-loop lesson)
        for fid, f, s, why in reviews[:5]:            # at most 5 cards a run; the rest wait in the console
            read = explain(f)
            mid = notify.post(card(f, s, why, read))
            notify.react(mid, notify.APPROVE); notify.react(mid, notify.REJECT)
            con.execute("update dev_findings set explain=?, message_id=? where id=?", (read, mid, fid)); con.commit()
        poll(con)
    print("devicewatch:", " ".join(f"{k}={v}" for k, v in counts.items()))


def poll(con):
    for r in con.execute("select id, message_id from dev_findings where decision='review' and verdict is null "
                         "and message_id is not null").fetchall():
        yes = notify.reactors(r["message_id"], notify.APPROVE)
        no = notify.reactors(r["message_id"], notify.REJECT)
        if yes is None:                                  # message deleted: treat as no decision, stop asking
            con.execute("update dev_findings set verdict='dropped', decided_at=datetime('now') where id=?", (r["id"],))
        elif notify.owner() in (no or []):
            con.execute("update dev_findings set verdict='suspicious', decided_at=datetime('now') where id=?", (r["id"],))
            con.commit(); notify.resolve(r["message_id"], "❌ marked suspicious by the owner")
        elif notify.owner() in yes:
            con.execute("update dev_findings set verdict='normal', decided_at=datetime('now') where id=?", (r["id"],))
            con.commit(); notify.resolve(r["message_id"], "✅ normal, learned")
    con.commit()


if __name__ == "__main__":
    run(dry="--dry" in sys.argv)
