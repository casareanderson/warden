#!/usr/bin/env python3
"""incidents.py — join the dots between warden's detectors, and (SHADOW ONLY) ask a model what each incident needs.

  incidents.py              correlate new signals into incidents, record the owner's decisions, ask the model (timer: 10 min)
  incidents.py --no-model   correlate and label only
  incidents.py --report     how often the model's would-be action agreed with what the owner actually did
  incidents.py --list       the open incidents, biggest first
  incidents.py --facts ID   print the facts JSON the model sees for one incident, and stop

Every detector alerts on its own: a /24 probing `/.env` at Cloudflare, failing SSO logins and then signing in over SSH
is three unrelated alerts. Here those become ONE incident. Correlation is plain code: each signal is a fact with a stable
id (`ev:123`, `edge:<ray>`, `ids:9`, `intel:4`, `dev:2`, `integ:51`, `login:77`, `hb:3`) attached to the entities it
involves — an outside address's /24 (`net:`), a box (`box:`), a device (`device:`) — and an entity's facts within
`incidents.gap_hours` of each other are one incident. A fact can belong to two incidents (a failed sign-in is about the
box AND the address it came from); the incidents it links are shown as related.

The model never gathers or computes anything. It gets one incident's facts JSON and picks ONE action from a fixed list:
  ignore_learn · watch · ask_owner · propose_edge_block · propose_patch_now · check_box
with a confidence and at most two sentences of why, citing fact ids. A decision that cites an id the incident does not
have, or writes a number, address, name or CVE that is not in the facts, gets one repair round and is then WITHHELD
(stored with the reason), exactly like vulnbrief.py.

SHADOW MODE is the only mode: decisions are stored and shown in the console, never acted on and never sent anywhere.
This module does not import notify and never writes the ban, edge-ban or patch tables. What the owner actually decided
(edge-ban ✅/❌, integrity ✅/❌, device verdicts) is recorded next to each incident, and `--report` measures agreement,
so whether the model's judgement is any good is a number before it is ever allowed to do anything.

Config (warden.yml):
  incidents:
    mode: shadow                 # shadow | off
    gap_hours: 24                # quiet this long → the next signal opens a new incident
    min_weight: 8                # incidents lighter than this are listed but never sent to the model
    max_decisions: 20            # model calls per run (unchanged incidents are never re-asked)
    model: {url: …, models: […], key_secret: …}   # default: vuln.brief's
"""
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, secrets, views  # noqa: E402   (no notify: shadow mode never sends anything)

DB = config.DB
ACTIONS = ("ignore_learn", "watch", "ask_owner", "propose_edge_block", "propose_patch_now", "check_box")
BENIGN = {"ignore_learn", "watch"}                 # for agreement: "leave it" vs "someone should act"
LOOKBACK_DAYS = 7                                  # first run reads this far back
OVERLAP = timedelta(hours=1)                       # later runs re-read this much before the watermark (dedup by fact id)
MAX_FACTS = 30                                     # facts shown to the model per incident (heaviest first)
IDS_WEIGHT = {1: 8, 2: 4, 3: 1}
# Suricata's own decoder/stream anomalies at low severity: replies seen one way only, odd timestamps. Engine noise, not
# attacks (first real run: 1,040 of them made a search engine's /24 the second-biggest "incident").
IDS_NOISE_CATS = ("Generic Protocol Command Decode", "anomaly")
SYSTEM = """You triage security incidents for a small home network run by one person. warden, the tool that gathered
the facts, is detect-only: nothing you choose is carried out automatically, a person reviews it.
Choose exactly ONE action:
- ignore_learn: normal or harmless (scanners hitting 404s, the owner's own jobs); learn it, don't bother the owner
- watch: worth keeping an eye on, not worth the owner's attention yet
- ask_owner: something only the owner can judge (a new sign-in, a changed system file, a device doing something new)
- propose_edge_block: a hostile outside address or /24 that should be blocked at the edge
- propose_patch_now: an exposed, exploitable weakness on a box is involved and patching can't wait
- check_box: a box itself may be compromised or broken and someone should look at it
Use ONLY the facts JSON. Never add addresses, names, numbers or CVE ids that are not in it and never do arithmetic:
copy numbers exactly as written. When the facts are thin, prefer watch over a stronger action.
Reply with ONLY a JSON object: {"action": "<one of the six>", "confidence": <0 to 1>,
"why": "<at most two short sentences, plain UK English>", "cited": ["<fact ids from the facts>"]}"""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ts_of(s):
    return datetime.strptime(s[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      begin;
      create table if not exists incidents(id integer primary key, entity text, kind text, opened text, last_seen text,
        n_facts integer default 0, weight integer default 0, owner_label text, owner_source text);
      create index if not exists inc_entity on incidents(entity, last_seen);
      create table if not exists incident_facts(incident_id integer, fact_id text, ts text, source text, summary text,
        weight integer, data text, primary key(incident_id, fact_id));
      create index if not exists incf_fact on incident_facts(fact_id);
      create table if not exists incident_decisions(id integer primary key, incident_id integer, ts text, model text,
        facts_hash text, status text, action text, confidence real, why text, cited text, reason text,
        tokens_in integer, tokens_out integer, cost real);
      create index if not exists incd_inc on incident_decisions(incident_id, id);
      create table if not exists incident_state(key text primary key, value text);
      commit;
    """)                                         # one transaction: each DDL statement alone is an fsync on a slow disk
    return con


def has(con, t):
    return bool(con.execute("select 1 from sqlite_master where name=?", (t,)).fetchone())


# ── facts ────────────────────────────────────────────────────────────────────
# Never "outside": the LAN, loopback, link-local, CGNAT / VPN overlays (NetBird, Tailscale), IPv6 ULA, multicast.
# (Not ipaddress.is_global: it also rejects the documentation ranges, which real logs never carry but tests do.)
INSIDE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                            "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "::1/128",
                                            "fc00::/7", "fe80::/10", "ff00::/8", "::/128")]


def outside(ip):
    """The address object for an outside address, else None (inside ranges above, or not an address at all)."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    return None if any(a in n for n in INSIDE if n.version == a.version) else a


def net_key(a):
    return "net:" + str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))


def gather(con, since):
    """Every signal since `since` as a fact: {id, ts, source, entities, summary, weight, data}. Own addresses dropped."""
    mine = views.self_nets()
    s = fmt(since)
    out = []

    def net(ip):
        a = outside(ip)
        return net_key(a) if a and not views.is_self(str(a), mine) else None

    dev_by_ip = {}
    if has(con, "devices"):
        for r in con.execute("select ip, coalesce(identity, mac) ident, name from devices where ip is not null"):
            dev_by_ip[r["ip"]] = (r["ident"], r["name"])
    if has(con, "events"):
        for r in con.execute("select id, ts, source, ip, kind, detail, score from events where ts > ? and ip != ''", (s,)):
            n = net(r["ip"])
            if n:
                out.append(dict(id=f"ev:{r['id']}", ts=r["ts"], source=r["source"], entities=[n], weight=r["score"] or 1,
                                summary=f"{r['kind']} from {r['ip']}: {(r['detail'] or '')[:90]}",
                                data={"ip": r["ip"], "kind": r["kind"], "score": r["score"]}))
    if has(con, "edge_events"):
        for r in con.execute("select id, ts, ray, ip, cc, action, host, path, rule from edge_events where ts > ?", (s,)):
            n = net(r["ip"])
            if n and r["action"] in views.STOPPED:      # log/skip/link-maze rows are informational
                out.append(dict(id=f"edge:{r['ray'] or r['id']}", ts=r["ts"], source="cloudflare", entities=[n], weight=2,
                                summary=f"edge {r['action']} {r['ip']} ({r['cc'] or '?'}) {r['host'] or ''}{r['path'] or ''}"[:140],
                                data={"ip": r["ip"], "country": r["cc"], "action": r["action"], "rule": r["rule"]}))
    if has(con, "ids_alerts"):
        for r in con.execute("select id, ts, signature, category, severity, src, dst, dport from ids_alerts where ts > ?",
                             (s,)):
            if (r["severity"] or 3) >= 3 and (r["category"] in IDS_NOISE_CATS or (r["signature"] or "").startswith(
                    ("SURICATA ", "anomaly:"))):
                continue
            # direction matters: an outside SOURCE is suspect; a LAN device talking OUT is about the device, not the
            # address it talks to (first real run: outbound alerts to a search engine's /24 got "propose_edge_block")
            ents = [e for e in (net(r["src"]),) if e]
            for side in (r["src"], r["dst"]):
                if side in dev_by_ip:
                    ents.append(f"device:{dev_by_ip[side][0]}")
            if not ents and outside(r["dst"]) and not outside(r["src"]):
                ents.append(f"device:{r['src']}")             # a LAN address warden has no device row for
            if ents:
                out.append(dict(id=f"ids:{r['id']}", ts=r["ts"], source="ids", entities=sorted(set(ents)),
                                weight=IDS_WEIGHT.get(r["severity"], 1),
                                summary=f"IDS sev {r['severity']}: {r['signature']} {r['src']} → {r['dst']}:{r['dport']}"[:160],
                                data={"signature": r["signature"], "severity": r["severity"], "src": r["src"], "dst": r["dst"]}))
    if has(con, "intel_hits"):
        for r in con.execute("select id, ts, device, device_name, kind, indicator, feed from intel_hits where ts > ? "
                             "and kind != 'false-positive'", (s,)):
            ident = dev_by_ip.get(r["device"], (r["device"], None))[0]
            out.append(dict(id=f"intel:{r['id']}", ts=r["ts"], source="threat-intel", entities=[f"device:{ident}"], weight=8,
                            summary=f"{r['device_name'] or r['device']} hit {r['kind']} {r['indicator']} ({r['feed']})"[:160],
                            data={"device": r["device_name"] or r["device"], "indicator": r["indicator"], "feed": r["feed"]}))
    if has(con, "dev_findings"):
        for r in con.execute("select id, ts, identity, domain, score, decision from dev_findings where ts > ? "
                             "and decision != 'learned'", (s,)):
            out.append(dict(id=f"dev:{r['id']}", ts=r["ts"], source="device-behaviour", entities=[f"device:{r['identity']}"],
                            weight=max(1, (r["score"] or 0) // 10), summary=f"new lookup {r['domain']} (score {r['score']})",
                            data={"domain": r["domain"], "score": r["score"], "decision": r["decision"]}))
    if has(con, "integ_find"):
        for r in con.execute("select id, ts, target, kind, item, change, status from integ_find where ts > ?", (s,)):
            out.append(dict(id=f"integ:{r['id']}", ts=r["ts"], source="integrity", entities=[f"box:{r['target']}"],
                            weight=10 if r["kind"] == "bad" else 3,
                            summary=f"{r['change']} {r['kind']} {r['item']}"[:160],
                            data={"kind": r["kind"], "item": r["item"], "change": r["change"], "status": r["status"]}))
    if has(con, "logins"):
        for r in con.execute("select id, ts, target, user, src, method, ok, new from logins where ts > ? and self = 0 "
                             "and (ok = 0 or new = 1)", (s,)):
            ents = [f"box:{r['target']}"] + [e for e in (net(r["src"]),) if e]
            what = "NEW sign-in" if r["ok"] else "failed sign-in"
            out.append(dict(id=f"login:{r['id']}", ts=r["ts"], source="sign-in", entities=ents, weight=6 if r["ok"] else 1,
                            summary=f"{what} {r['user']} from {r['src']} ({r['method']})",
                            data={"user": r["user"], "src": r["src"], "method": r["method"], "ok": r["ok"]}))
    if has(con, "hb_events"):
        for r in con.execute("select id, ts, target, event, detail from hb_events where ts > ? and event != 'gone'", (s,)):
            out.append(dict(id=f"hb:{r['id']}", ts=r["ts"], source="heartbeat", entities=[f"box:{r['target']}"],
                            weight={"down": 4, "stopped": 3, "rebooted": 3}.get(r["event"], 0),
                            summary=f"{r['event']} {r['detail'] or ''}"[:140], data={"event": r["event"]}))
    if has(con, "agent_alerts"):
        for r in con.execute("select id, ts, agent, host, dest_ip, kind, feed from agent_alerts where ts > ?", (s,)):
            n = net(r["dest_ip"])
            if n:
                out.append(dict(id=f"agent:{r['id']}", ts=r["ts"], source="agent-egress", entities=[n], weight=9,
                                summary=f"Hermes agent {r['agent']} on {r['host']} reached {r['dest_ip']} ({r['kind']}/{r['feed']})"[:160],
                                data={"agent": r["agent"], "host": r["host"], "dest": r["dest_ip"], "kind": r["kind"], "feed": r["feed"]}))
    return sorted(out, key=lambda f: f["ts"])


# ── correlation ──────────────────────────────────────────────────────────────
def correlate(con):
    """Attach new facts to the open incident of each of their entities (or open one). Returns facts added."""
    gap = timedelta(hours=float((config.get("incidents") or {}).get("gap_hours") or 24))
    wm = con.execute("select value from incident_state where key='watermark'").fetchone()
    since = ts_of(wm["value"]) - OVERLAP if wm else datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    added, newest = 0, wm["value"] if wm else None
    for f in gather(con, since):
        for ent in f["entities"]:
            row = con.execute("select id, last_seen from incidents where entity=? and last_seen >= ? "
                              "order by last_seen desc limit 1", (ent, fmt(ts_of(f["ts"]) - gap))).fetchone()
            if row:
                iid = row["id"]
            else:
                iid = con.execute("insert into incidents(entity, kind, opened, last_seen) values(?,?,?,?)",
                                  (ent, ent.split(":", 1)[0], f["ts"][:19], f["ts"][:19])).lastrowid
            cur = con.execute("insert or ignore into incident_facts values(?,?,?,?,?,?,?)",
                              (iid, f["id"], f["ts"][:19], f["source"], f["summary"], f["weight"], json.dumps(f["data"])))
            if cur.rowcount == 1:
                con.execute("update incidents set last_seen=max(last_seen, ?), n_facts=n_facts+1, weight=weight+? "
                            "where id=?", (f["ts"][:19], f["weight"], iid))
                added += 1
        newest = max(newest or f["ts"][:19], f["ts"][:19])
    if newest:
        con.execute("insert or replace into incident_state values('watermark', ?)", (newest,))
    con.commit()
    return added


def facts_for(con, iid):
    """What the model sees: the incident, its heaviest facts, counts by source, and the entities it shares facts with."""
    inc = con.execute("select * from incidents where id=?", (iid,)).fetchone()
    rows = con.execute("select fact_id, ts, source, summary, weight, data from incident_facts where incident_id=? "
                       "order by weight desc, ts desc", (iid,)).fetchall()
    counts = {}
    for r in rows:
        counts[r["source"]] = counts.get(r["source"], 0) + 1
    related = [r[0] for r in con.execute(
        "select distinct i.entity from incident_facts a join incident_facts b on a.fact_id=b.fact_id "
        "join incidents i on i.id=b.incident_id where a.incident_id=? and b.incident_id!=?", (iid, iid))]
    return {"incident": inc["entity"], "first_seen": inc["opened"], "last_seen": inc["last_seen"],
            "signals": len(rows), "by_source": counts, "related_incidents": related[:10],
            "facts": [{"id": r["fact_id"], "ts": r["ts"], "source": r["source"], "what": r["summary"],
                       **json.loads(r["data"] or "{}")} for r in rows[:MAX_FACTS]],
            **({"more_facts_not_shown": len(rows) - MAX_FACTS} if len(rows) > MAX_FACTS else {})}


def facts_hash(f):
    return hashlib.sha256(json.dumps(sorted(x["id"] for x in f["facts"]) + [f["signals"]]).encode()).hexdigest()[:16]


# ── what the owner actually decided (for agreement, and stored as labels for later few-shot use) ─────────────
def label(con):
    """owner_label = 'benign' | 'act' where the owner already decided about something in the incident."""
    n = 0
    for inc in con.execute("select id, entity, kind from incidents where owner_label is null").fetchall():
        lab = src = None
        fids = [r[0] for r in con.execute("select fact_id from incident_facts where incident_id=?", (inc["id"],))]
        if inc["kind"] == "net" and has(con, "edge_bans"):
            netw = ipaddress.ip_network(inc["entity"][4:], strict=False)
            for b in con.execute("select target, status from edge_bans"):
                try:
                    hit = ipaddress.ip_network(b["target"], strict=False).overlaps(netw)
                except ValueError:
                    continue
                if hit and b["status"] in ("active", "expired"):
                    lab, src = "act", f"edge ban {b['target']} approved"
                elif hit and b["status"] in ("rejected", "declined"):
                    lab, src = "benign", f"edge ban {b['target']} rejected"
        ids = [f.split(":", 1)[1] for f in fids if f.startswith("integ:")]
        if ids and not lab:
            for r in con.execute(f"select note from integ_find where id in ({','.join('?' * len(ids))})", ids):
                note = r["note"] or ""
                if note.startswith("owner ❌"):
                    lab, src = "act", "integrity change: owner ❌"
                    break
                if note.startswith("owner ✅"):
                    lab, src = "benign", "integrity change: owner ✅"
        ids = [f.split(":", 1)[1] for f in fids if f.startswith("dev:")]
        if ids and not lab:
            for r in con.execute(f"select verdict from dev_findings where id in ({','.join('?' * len(ids))})", ids):
                if r["verdict"] in ("normal", "suspicious"):
                    lab, src = ("benign" if r["verdict"] == "normal" else "act"), f"device verdict {r['verdict']}"
        if lab:
            con.execute("update incidents set owner_label=?, owner_source=? where id=?", (lab, src, inc["id"]))
            n += 1
    con.commit()
    # TODO (later PR): feed owner-labelled incidents back to the model as few-shot examples once there are enough.
    return n


# ── the model (shadow) ───────────────────────────────────────────────────────
def model_cfg():
    c = (config.get("incidents") or {}).get("model") or config.get("vuln.brief")
    return c or None


def ask(f, fix=None):
    cfg = model_cfg()
    key = secrets.get(cfg.get("key_secret") or "OPENROUTER_API_KEY") or ""
    url = (cfg.get("url") or "https://openrouter.ai/api/v1").rstrip("/")
    errs = []
    for model in cfg.get("models") or [cfg.get("model") or "qwen/qwen3.7-flash"]:
        try:
            body = {"model": model, "temperature": 0.1, "max_tokens": 400,
                    "reasoning": {"enabled": False},          # same trap as vulnbrief: thinking eats the whole budget
                    "messages": [{"role": "system", "content": SYSTEM},
                                 {"role": "user", "content": json.dumps(f, separators=(",", ":"))}]
                    + ([{"role": "assistant", "content": fix[0]},
                        {"role": "user", "content": f"Rejected by the fact check: {fix[1]}. Answer again using only ids, "
                         "names and numbers that appear in the facts."}] if fix else [])}
            if "openrouter.ai" in url:
                body["usage"] = {"include": True}             # OpenRouter reports the cost of the call
            r = requests.post(url + "/chat/completions", timeout=90, json=body,
                              headers={"Authorization": f"Bearer {key}"} if key else {})
            r.raise_for_status()
            j = r.json()
            text = re.sub(r"(?s)<think>.*?</think>", "", (j["choices"][0]["message"]["content"] or "")).strip()
            if text:
                return model, text, j.get("usage") or {}
            errs.append(f"{model}: empty answer")
        except Exception as e:  # noqa: BLE001 — try the next model
            errs.append(f"{model}: {type(e).__name__} {str(e)[:100]}")
    raise RuntimeError("; ".join(errs))


def parse(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in the answer")
    return json.loads(m.group(0))


CVE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I)
HOSTISH = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b", re.I)


def check(d, f):
    """'' when the decision is well-formed and only cites what is in the incident, else why it is withheld."""
    if d.get("action") not in ACTIONS:
        return f"action {d.get('action')!r} is not one of the six"
    try:
        c = float(d.get("confidence"))
    except (TypeError, ValueError):
        return "confidence is not a number"
    if not 0 <= c <= 1:
        return "confidence is outside 0-1"
    why = str(d.get("why") or "").strip()
    if not why or len(why) > 400 or len(re.findall(r"[.!?](\s|$)", why)) > 2:
        return "why is missing, too long or more than two sentences"
    ids = {x["id"] for x in f["facts"]}
    cited = d.get("cited") or []
    if not isinstance(cited, list) or not cited:
        return "cites no fact ids"
    bad = [x for x in cited if x not in ids]
    if bad:
        return "cites ids the incident does not have: " + ", ".join(map(str, bad[:5]))
    blob = json.dumps(f).lower()
    for x in CVE.findall(why):
        if x.lower() not in blob:
            return f"names {x}, which is not in the facts"
    for tok in re.findall(r"[\w.:/@-]*\d[\w.:/@%-]*", why):          # every number, address, version, id
        t = tok.strip(".,;:()[]'\"").rstrip("-")
        if t and t.lower() not in blob:
            return f"uses '{t}', which is not in the facts"
    for h in HOSTISH.findall(why):                                  # host and domain names
        if h.lower() not in blob:
            return f"names '{h}', which is not in the facts"
    return ""


def decide(con, cap=None):
    """Ask about the heaviest incidents whose facts changed since their last decision. Shadow: stored, never acted on."""
    if not model_cfg():
        print("incidents: no model configured (incidents.model or vuln.brief) — correlation only")
        return {"decided": 0, "withheld": 0}
    c = config.get("incidents") or {}
    cap = cap if cap is not None else int(c.get("max_decisions") or 20)
    minw = int(c.get("min_weight") or 8)
    done = {"decided": 0, "withheld": 0}
    for inc in con.execute("select id from incidents where weight >= ? order by weight desc, last_seen desc",
                           (minw,)).fetchall():
        if done["decided"] + done["withheld"] >= cap:
            break
        f = facts_for(con, inc["id"])
        h = facts_hash(f)
        prev = con.execute("select facts_hash from incident_decisions where incident_id=? order by id desc limit 1",
                           (inc["id"],)).fetchone()
        if prev and prev["facts_hash"] == h:
            continue                                     # nothing new since the last answer
        model, text, usage, d, reason = "", "", {}, {}, ""
        try:
            model, text, usage = ask(f)
            try:
                d = parse(text)
                reason = check(d, f)
            except ValueError as e:
                reason = f"not valid JSON ({e})"
            if reason:                                   # one repair round
                model, text, u2 = ask(f, fix=(text, reason))
                usage = {k: (usage.get(k) or 0) + (u2.get(k) or 0) for k in ("prompt_tokens", "completion_tokens", "cost")}
                try:
                    d = parse(text)
                    reason = check(d, f)
                except ValueError as e:
                    reason = f"not valid JSON ({e})"
        except RuntimeError as e:
            reason = f"model unavailable ({e})"
        status = "ok" if not reason else "withheld"
        con.execute("insert into incident_decisions(incident_id, ts, model, facts_hash, status, action, confidence, why, "
                    "cited, reason, tokens_in, tokens_out, cost) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (inc["id"], now(), model, h, status, d.get("action") if not reason else None,
                     float(d["confidence"]) if not reason else None, str(d.get("why") or "")[:400] if not reason else None,
                     json.dumps(d.get("cited") or []) if not reason else None, reason or None,
                     usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("cost")))
        con.commit()
        done["decided" if status == "ok" else "withheld"] += 1
    return done


# ── reports ──────────────────────────────────────────────────────────────────
def latest(con):
    return con.execute("select i.*, d.status, d.action, d.confidence, d.why, d.reason from incidents i left join "
                       "incident_decisions d on d.id = (select max(id) from incident_decisions where incident_id=i.id)"
                       ).fetchall()


def report(con):
    rows = latest(con)
    decided = [r for r in rows if r["status"] == "ok"]
    agree = sum(1 for r in decided if r["owner_label"] and (r["action"] in BENIGN) == (r["owner_label"] == "benign"))
    disagree = sum(1 for r in decided if r["owner_label"]) - agree
    tot = con.execute("select count(*) n, sum(status='withheld') w, sum(tokens_in) ti, sum(tokens_out) tout, sum(cost) c "
                      "from incident_decisions").fetchone()
    by = {}
    for r in decided:
        by[r["action"]] = by.get(r["action"], 0) + 1
    return {"incidents": len(rows), "decided": len(decided), "by_action": by, "agree": agree, "disagree": disagree,
            "no_owner_decision": len(decided) - agree - disagree, "withheld_all_time": tot["w"] or 0,
            "decisions_all_time": tot["n"], "tokens_in": tot["ti"] or 0, "tokens_out": tot["tout"] or 0,
            "cost_usd": round(tot["c"] or 0, 4)}


def main():
    a = sys.argv[1:]
    mode = str((config.get("incidents") or {}).get("mode") or "shadow")
    if mode not in ("shadow", "off"):
        print(f"incidents: mode {mode!r} is not supported (shadow | off) — doing nothing")
        return 0
    if mode == "off":
        print("incidents: off")
        return 0
    con = db()
    if "--report" in a:
        print(json.dumps(report(con), indent=1))
        return 0
    if "--facts" in a:
        print(json.dumps(facts_for(con, int(a[a.index("--facts") + 1])), indent=1))
        return 0
    if "--list" in a:
        for r in sorted(latest(con), key=lambda r: -r["weight"])[:40]:
            print(f"#{r['id']:<5} w{r['weight']:<5} {r['entity']:<28} {r['n_facts']:>5} facts  {r['opened']} → "
                  f"{r['last_seen']}  {r['action'] or r['reason'] or ''}  {r['owner_label'] or ''}")
        return 0
    added = correlate(con)
    labelled = label(con)
    done = {"decided": 0, "withheld": 0} if "--no-model" in a else decide(con)
    print(f"incidents (shadow): +{added} facts, {labelled} newly labelled by the owner's decisions, "
          f"{done['decided']} decided, {done['withheld']} withheld")
    return 0


if __name__ == "__main__":
    sys.exit(main())
