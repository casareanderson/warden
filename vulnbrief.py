#!/usr/bin/env python3
"""vulnbrief.py — the "fix first" briefing on top of the vulnerability scan (built 2026-10-10). Optional.

  vulnbrief.py            build facts → ask the model → fact-check → store (runs after vulnscan)
  vulnbrief.py --facts    print the facts the model would see, and stop
  vulnbrief.py --send     also post it to the alert channel (only when the must-fix list changed)

The scan finds and ranks. This turns the ranking into a short, plain "do this first, because" list. The model never
gathers or computes anything; it gets a facts JSON built here (KEV, EPSS, fix versions, which boxes and images, how a
container can be updated). Then every CVE id, box, image, package and version it writes is checked against those
facts, and a briefing that names anything else is WITHHELD, not shown. Nothing here changes scan results or alerts.

Config (warden.yml), any OpenAI-compatible endpoint (OpenRouter, a local Ollama, …):
  vuln:
    brief: {url: https://openrouter.ai/api/v1, models: [deepseek/deepseek-v4-flash-0731, qwen/qwen3.7-flash],
            key_secret: OPENROUTER_API_KEY}
Without `vuln.brief` this does nothing.
"""
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, notify, secrets  # noqa: E402

DB = config.DB
TOP = 25
SYSTEM = """You write the "fix first" briefing for a homelab's vulnerability scanner.
Use ONLY the facts JSON you are given. Never add CVE ids, versions, boxes, images, packages or numbers that are not in it,
and never do arithmetic: every number you write must be copied from the facts.
Write at most 6 numbered actions, most urgent first, in plain UK English, under 1100 characters in total.
Order: anything known-exploited (kev true) first, then high exploit chance (epss_pct_str), then critical with a fix;
within each, anything internet_facing "yes" comes first, and say which public hostname reaches it.
Group the same fix together (one image update can clear several CVEs). For each action say WHAT to do (patch which box,
or update which image and how: use the container's `update` field), and WHY in one short clause (cite the CVE ids and
kev/epss exactly as written). Write package, image and box names exactly as they appear, never shortened or joined
into new names. If nothing is known-exploited or likely, say so in one line. No preamble, no sign-off."""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.execute("create table if not exists vuln_brief(id integer primary key, ts text, model text, status text, "
                "text text, reason text, facts_hash text, must text)")
    return con


def facts(con):
    """Deterministic facts: the top must-fix CVEs with everything the model may cite, as strings it can copy."""
    cols = {r[1] for r in con.execute("pragma table_info(vulns)")}
    e = "max(v.epss) epss, max(v.epss_pct) epss_pct," if "epss" in cols else "null epss, null epss_pct,"
    rows = con.execute(f"""
        select v.vid, max(v.kev) kev, {e} max(case v.severity when 'CRITICAL' then 4 when 'HIGH' then 3
               when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end) sevn, max(v.title) title
        from vulns v where v.fixed!='' or v.kev=1 group by v.vid
        order by kev desc, (coalesce(max(v.epss),0)>=0.1) desc, sevn desc, coalesce(max(v.epss),0) desc
        limit {TOP}""").fetchall()
    sevname = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}
    advice = {}
    if con.execute("select 1 from sqlite_master where name='img_advice'").fetchone():
        for a in con.execute("select * from img_advice"):
            a = dict(a)
            advice.setdefault(a.get("image") or "", []).append(a)
    names = {r["target"]: r["name"] for r in con.execute("select target, name from vuln_targets")}
    out = []
    for r in rows:
        where = []
        ex = ", exposed" if "exposed" in cols else ", null exposed"
        for w in con.execute(f"select target, pkg, installed, fixed, image{ex} from vulns where vid=? "
                             "order by target, image, pkg", (r["vid"],)):
            item = {"box": names.get(w["target"], w["target"]), "package": w["pkg"], "installed": w["installed"],
                    "fixed_in": w["fixed"] or "no fix yet",
                    "internet_facing": f"yes, via {w['exposed']}" if w["exposed"] else "no"}
            if w["image"]:
                item["image"] = w["image"]
                adv = advice.get(w["image"]) or []
                if adv:
                    item["container"] = adv[0].get("container")
                    item["update"] = {"recreate": "re-create it: a newer image is already pulled",
                                      "pull": "pull the newer image, then re-create",
                                      }.get(adv[0].get("action"), "manual: " + str(adv[0].get("why") or "")[:120])
            elif w["fixed"]:
                item["update"] = "patch the box (warden → Vulnerabilities → Patch)"
            else:
                item["update"] = "no fix released yet: nothing to install, keep watching"
            where.append(item)
        seen, uniq = set(), []
        for w in where:                                  # one line per box/image/package
            k = json.dumps(w, sort_keys=True)
            if k not in seen:
                seen.add(k)
                uniq.append(w)
        out.append({"cve": r["vid"], "kev": bool(r["kev"]), "severity": sevname[r["sevn"]],
                    "epss_pct_str": (f"{r['epss'] * 100:.1f}%" if r["epss"] is not None else "not scored"),
                    "title": (r["title"] or "")[:140], "where": uniq[:8],
                    **({"more_places": len(uniq) - 8} if len(uniq) > 8 else {})})
    totals = dict(con.execute("select count(distinct case when kev=1 then vid end) known_exploited, "
                              "count(distinct case when fixed!='' and severity='CRITICAL' then vid end) "
                              "critical_with_fix from vulns").fetchone())
    return {"generated": now(), "totals": totals, "must_fix": out}


def ask(f, fix=None):
    cfg = config.get("vuln.brief") or {}
    key = secrets.get(cfg.get("key_secret") or "OPENROUTER_API_KEY") or ""
    url = (cfg.get("url") or "https://openrouter.ai/api/v1").rstrip("/") + "/chat/completions"
    errs = []
    for model in cfg.get("models") or [cfg.get("model") or "qwen/qwen3.7-flash"]:
        try:
            r = requests.post(url, timeout=120, headers={"Authorization": f"Bearer {key}"} if key else {},
                              # reasoning OFF: qwen3.7-flash ignored effort=low and spent all 4,000 tokens thinking (no answer);
                              # this is copying facts into prose, not a puzzle (2026-10-10)
                              json={"model": model, "temperature": 0.1, "max_tokens": 1500,
                                    "reasoning": {"enabled": False}, "messages": [
                                  {"role": "system", "content": SYSTEM},
                                  {"role": "user", "content": json.dumps(f, separators=(",", ":"))}]
                                  + ([{"role": "assistant", "content": fix[0]},
                                      {"role": "user", "content": f"Rejected by the fact check: {fix[1]}. Rewrite it "
                                       "using only names and numbers that appear in the facts."}] if fix else [])})
            r.raise_for_status()
            text = (r.json()["choices"][0]["message"]["content"] or "").strip()
            text = re.sub(r"(?s)<think>.*?</think>", "", text).strip()   # reasoning models
            if text:
                return model, text
            errs.append(f"{model}: empty answer")
        except Exception as e:  # noqa: BLE001 — try the next model
            errs.append(f"{model}: {type(e).__name__} {str(e)[:100]}")
    raise RuntimeError("; ".join(errs) or "no model configured")


ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|GO-\d{4}-\d+|PYSEC-\d{4}-\d+)\b", re.I)


def check(text, f):
    """'' when every cited fact is in the facts JSON, else the reason it is withheld."""
    blob = json.dumps(f)
    low = blob.lower()
    ids = {i.upper() for i in ID.findall(text)}
    bad = sorted(i for i in ids if i not in blob.upper())
    if bad:
        return "names CVE ids not in the scan: " + ", ".join(bad[:5])
    if not ids and f["must_fix"]:
        return "cites no CVE ids at all"
    for tok in re.findall(r"[\w.+:/@~-]*\d[\w.+:/@~%-]*", text):
        t = tok.strip(".,;:()[]'\"").rstrip("-")
        if not t or re.fullmatch(r"\d{1,2}[.)]?", t):        # list numbering, small counts like "2 images"
            continue
        if t.lower() not in low and not all(p and p.lower() in low for p in t.split("/")):
            return f"uses '{t}', which is not in the facts"
    for tok in re.findall(r"`([^`]+)`", text):              # anything quoted as a name must exist verbatim
        if tok.lower() not in low:
            return f"names '{tok}', which is not in the facts"
    for a, b in re.findall(r"\b([a-z][\w.+-]{2,})/([a-z][\w.+-]{2,})\b", text):   # joined package names
        for p in (a, b):
            if p.lower() not in low:
                return f"names '{p}', which is not in the facts"
    return ""


def main():
    a = sys.argv[1:]
    if not config.get("vuln.brief") and "--facts" not in a:
        print("AI briefing off (no vuln.brief in warden.yml)")
        return 0
    con = db()
    f = facts(con)
    if "--facts" in a:
        print(json.dumps(f, indent=1))
        return 0
    must = sorted(m["cve"] for m in f["must_fix"] if m["kev"] or m["epss_pct_str"] != "not scored")
    h = hashlib.sha256(json.dumps(f["must_fix"], sort_keys=True).encode()).hexdigest()[:16]
    prev = con.execute("select facts_hash, must, status from vuln_brief order by id desc limit 1").fetchone()
    if prev and prev["facts_hash"] == h and prev["status"] == "ok":
        print("facts unchanged since the last briefing; kept it")
        return 0
    try:
        model, text = ask(f)
        reason = check(text, f)
        if reason:                                      # one repair round: tell it what failed, check again
            model, text = ask(f, fix=(text, reason))
            reason = check(text, f)
    except Exception as e:  # noqa: BLE001
        model, text, reason = "", "", f"model unavailable ({e})"
    status = "ok" if not reason else "withheld"
    con.execute("insert into vuln_brief(ts, model, status, text, reason, facts_hash, must) values(?,?,?,?,?,?,?)",
                (now(), model, status, text, reason, h, json.dumps(must)))
    con.execute("delete from vuln_brief where id not in (select id from vuln_brief order by id desc limit 60)")
    con.commit()
    print(f"{status}: {reason or model}\n{text}")
    if "--send" in a and status == "ok" and (not prev or prev["must"] != json.dumps(must)):
        notify.send(("🩹 **Fix first** (AI-written from warden's scan, fact-checked)\n" + text)[:1990])
    return 0


if __name__ == "__main__":
    sys.exit(main())
