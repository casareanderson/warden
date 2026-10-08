#!/usr/bin/env python3
"""warden-facts.py — deterministic warden v2 facts for an agent fact gatherer (read-only, no LLM).

Meant to be called from an agent's fact gatherer (the author's runs it daily inside an IT-admin
review). Prints plain lines; anything that needs action ends in `<-- ...` so the review picks it up.
Boxes are named CT<id> / node <ip> / host name so a fact validator can match every citation.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config  # noqa: E402

DB = config.DB
TIMERS = ["warden", "warden-netids", "warden-netintel", "warden-harden", "warden-intel", "warden-vulnscan", "warden-integrity-sweep", "warden-integrity-deep",
          "warden-integrity-poll", "warden-patcher", "warden-patch-auto", "warden-edgeban-propose",
          "warden-edgeban-poll", "warden-geo"]
SERVICES = ["warden-ui", "trivy-server"]


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True).stdout.strip()


def age_h(ts):
    if not ts:
        return None
    try:
        # every warden timestamp is UTC — mktime() would read it as local time (BST = 1 h off)
        return (time.time() - __import__("calendar").timegm(time.strptime(ts[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))) / 3600
    except ValueError:
        return None


def label(target, name):
    if target.startswith("ct:"):
        return f"CT{target[3:]} {name}"
    if target.startswith("node:"):
        return f"node {target[5:]} ({name})"
    return name


def main():
    if not os.path.exists(DB):
        print("--- WARDEN v2\n  DB MISSING — GAP"); return
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    have = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}

    print("--- WARDEN v2 — ARE ALL THE PARTS RUNNING")
    for t in TIMERS:
        if sh("systemctl", "list-unit-files", f"{t}.timer", "--no-legend") == "":
            print(f"  timer {t:<24} NOT INSTALLED   <-- missing component"); continue
        act = sh("systemctl", "is-active", f"{t}.timer")
        res = sh("systemctl", "show", "-p", "Result", "--value", f"{t}.service")
        flag = "" if act == "active" and res in ("success", "") else \
            f"   <-- {'timer not active' if act != 'active' else 'last run FAILED (' + res + ')'}"
        print(f"  timer {t:<24} {act:<8} last-result={res or '-'}{flag}")
    for s in SERVICES:
        act = sh("systemctl", "is-active", s)
        print(f"  service {s:<22} {act}{'' if act == 'active' else '   <-- DOWN'}")

    # freshness — a component that runs but produces stale data is the classic silent failure
    try:
        meta = json.load(open(os.path.join(config.get("vuln.cache") or "/var/cache/trivy", "db", "metadata.json")))
        a = age_h(meta.get("UpdatedAt", "")[:19])
        print(f"  trivy vuln DB age: {a:.0f}h" + ("   <-- stale (>72h): vulnscan DB update failing" if a and a > 72 else ""))
    except Exception:  # noqa: BLE001
        print("  trivy vuln DB: unreadable   <-- check the trivy cache (vuln.cache)")
    for src, maxh, what in (("cf-edge", 3, "Cloudflare edge events"), ("surface", 3, "attack-surface snapshot"),
                            ("suricata", 1, "Suricata IDS"),
                            ("adguard", 1, "router DNS log (AdGuard)"), ("conntrack", 1, "router connection table")):
        r = c.execute("select ts, note from runs where source=? order by id desc limit 1", (src,)).fetchone()
        if not r:
            print(f"  {what}: never ran   <-- GAP"); continue
        a = age_h(r[0]); note = r[1] or ""
        if note.startswith("skipped"):
            print(f"  {what}: {note}"); continue
        flag = "   <-- BLIND: " + note if note.startswith("BLIND") else \
            f"   <-- stale ({a:.0f}h)" if a and a > maxh else ""
        print(f"  {what}: last {a:.1f}h ago{flag}")

    if "vuln_targets" in have:
        print("--- WARDEN v2 — VULNERABILITIES (daily scan, CISA KEV-ranked)")
        last = c.execute("select max(last_scan) from vuln_targets").fetchone()[0]
        a = age_h(last)
        print(f"  last scan: {a:.0f}h ago" + ("   <-- stale (>30h): warden-vulnscan not running" if a and a > 30 else ""))
        for (tgt, name, st, note, kev, crit, fix, upg, reb, os_) in c.execute(
                "select target,name,status,note,n_kev,n_crit_fix,n_fixable,upgradable,reboot_required,os from vuln_targets "
                "order by target"):
            bits = []
            if st not in ("ok",):
                bits.append(f"scan {st}: {(note or '')[:80]}")
            if kev:
                bits.append(f"{kev} KNOWN-EXPLOITED (KEV)")
            if crit:
                bits.append(f"{crit} critical with fix")
            if reb:
                bits.append("reboot pending" + (" — Proxmox node, manual" if tgt.startswith("node:") else ""))
            if tgt.startswith("fw:") and note and "UPDATE AVAILABLE" in note:
                bits.append(note.split(" · ")[0])
            flag = ("   <-- " + "; ".join(bits)) if bits else ""
            print(f"  {label(tgt, name):<32} fixable={fix or 0:<4} upgradable={'-' if upg is None else upg:<4}{flag}")

    if "integ_runs" in have:
        print("--- WARDEN v2 — ENDPOINT INTEGRITY (agentless drift)")
        names = dict(c.execute("select target, name from vuln_targets")) if "vuln_targets" in have else {}
        for tgt, ts, st, note in c.execute("select target, ts, status, note from integ_runs order by target"):
            n_open = c.execute("select count(*) from integ_find where target=? and status='open'", (tgt,)).fetchone()[0]
            a = age_h(ts)
            bits = []
            if st != "ok":
                bits.append(f"sweep {st}: {(note or '')[:80]}")
            if a and a > 3:
                bits.append(f"last sweep {a:.0f}h ago")
            if n_open:
                bits.append(f"{n_open} OPEN drift finding(s) — owner to ✅/❌ on the alert channel")
            info = f" ({note})" if note and st == "ok" and "restart" in note else ""
            print(f"  {label(tgt, names.get(tgt, tgt)):<32} open={n_open}{info}" + (("   <-- " + "; ".join(bits)) if bits else ""))

    if "patch_jobs" in have:
        print("--- WARDEN v2 — PATCHING (button/agent request → plan → owner ✅)")
        pend = list(c.execute("select id, target, name, requested from patch_jobs where status='pending' order by id"))
        for i, t, n, r in pend:
            print(f"  plan #{i} {label(t, n)} waiting for owner ✅ since {r}   <-- awaiting approval on the alert channel")
        for i, t, n, r, res in c.execute("select id,target,name,finished,result from patch_jobs where status='failed' "
                                         "and finished > datetime('now','-7 days')"):
            print(f"  job #{i} {label(t, n)} FAILED {r}: {(res or '')[:100]}   <-- investigate")
        for i, t, n, r in c.execute("select id,target,name,decided from patch_jobs where status='running' "
                                    "and decided < datetime('now','-2 hours')"):
            print(f"  job #{i} {label(t, n)} RUNNING since {r}   <-- stuck >2h?")
        cols = {r[1] for r in c.execute("pragma table_info(patch_jobs)")}
        if "run_after" in cols:
            for i, t, n, ra, why in c.execute("select id,target,name,run_after,timing_why from patch_jobs where "
                                              "status='approved' and run_after > datetime('now')"):
                print(f"  job #{i} {label(t, n)} approved, scheduled {ra} UTC ({why})")
        done = c.execute("select count(*) from patch_jobs where status='done' and finished > datetime('now','-7 days')"
                         ).fetchone()[0]
        print(f"  patched in last 7 days: {done}; plans awaiting ✅: {len(pend)}")

    if "edge_bans" in have:
        n = c.execute("select count(*) from edge_bans where status='pending'").fetchone()[0]
        act = c.execute("select count(*) from edge_bans where status='active'").fetchone()[0]
        print(f"--- WARDEN v2 — EDGE BLOCKLIST\n  active bans: {act}; proposals awaiting ✅: {n}"
              + ("   <-- owner decision pending" if n else ""))


if __name__ == "__main__":
    main()
