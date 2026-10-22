#!/usr/bin/env python3
"""webscan.py — app-layer web vulnerability scan (DAST) for the estate's own sites (built 2026-10-22). No LLM.

warden already scans the PACKAGES behind a public site (vulnscan.py → OSV.dev) and the EXPOSURE/config (intel.py).
This fills the gap the package scan can't: the web application itself — missing security headers, exposed panels,
known-CVE services (a vulnerable WordPress/Jenkins/etc.), default creds, and other signature-based web findings.

It runs `nuclei` (a fast, template-based DAST scanner) against the public names warden already knows (the attack
surface) plus anything named in `webscan.targets`, stores each finding, and posts NEW critical/high findings to
Discord. Detect-only and advisory: an app-layer bug is fixed in your code, not by `apt`, so nothing here patches
anything — it reports so you can.

    webscan.py            run one scan (timer: daily 04:00, after the 03:30 vuln scan)
    webscan.py --list     recent findings

warden.yml:
    webscan:
      nuclei: ""                 # path to the nuclei binary; "" = look on PATH. Off until nuclei is installed.
      targets: []                # extra URLs (https://host[:port]) to scan on top of the public names warden knows
      auto_targets: true         # also scan the public names in warden's attack-surface snapshot
      tags: cves,exposures,misconfig,technologies   # non-intrusive templates; leave fuzzing/dos out
      severity: medium,high,critical               # record/alert at or above this
      rate_limit: 10             # requests per second (be gentle with your own sites)

Hard rules:
  - Only the estate's own targets are ever scanned (public names from the surface snapshot + webscan.targets).
  - Detect-only. No finding here is ever auto-fixed; there is no patch path for app code.
  - No nuclei binary → silent skip, recorded in the runs table (never a crash).
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, notify  # noqa: E402

DB = config.DB
DEFAULT_TAGS = "cves,exposures,misconfig,technologies"
DEFAULT_SEVERITY = "medium,high,critical"


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer, parsed integer, note text);
      create table if not exists web_findings(
        id integer primary key, ts text, host text, template text, name text, severity text,
        matched text, curl text, seen integer, unique(host, template));
    """)
    return con


def nuclei_bin():
    p = config.get("webscan.nuclei")
    if p and os.path.exists(p):
        return p
    return shutil.which("nuclei")


def _targets():
    out = set(x for x in (config.get("webscan.targets") or []) if x)
    if config.get("webscan.auto_targets", True):
        try:
            import sqlite3 as _s
            c = _s.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=10)
            row = c.execute("select data from surface_snap order by id desc limit 1").fetchone()
            c.close()
            if row:
                snap = json.loads(row[0])
                for h in snap.get("hosts", []):
                    host = h.get("host")
                    if host and h.get("kind") != "lan-only":
                        out.add("https://" + host if not host.startswith("http") else host)
        except Exception:  # noqa: BLE001
            pass
    return sorted(out)


def _cmd(bin, targets):
    return [bin, "-jsonl", "-silent", "-no-color",
            "-severity", config.get("webscan.severity") or DEFAULT_SEVERITY,
            "-rate-limit", str(int(config.get("webscan.rate_limit") or 10)),
            "-timeout", "15", "-retries", "1",
            "-tags", config.get("webscan.tags") or DEFAULT_TAGS] + \
        [u for t in targets for u in ("-u", t)]


def parse(lines):
    """nuclei -jsonl lines → finding dicts. Anything malformed is skipped, never a crash."""
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln or not ln.startswith("{"):
            continue
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        info = j.get("info") or {}
        out.append({"host": j.get("host") or "", "template": j.get("template-id") or "",
                    "name": (info.get("name") or j.get("template-id") or "")[:160],
                    "severity": (info.get("severity") or "unknown").lower(),
                    "matched": (j.get("matched-at") or "")[:200],
                    "curl": (j.get("curl-command") or "")[:400]})
    return out


def scan():
    con = db()
    bin = nuclei_bin()
    if not bin:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',0,0,"
                    "'nuclei not installed — skipped (see webscan: in warden.yml)')")
        con.commit()
        print("webscan: nuclei not installed — skipped")
        return 0
    targets = _targets()
    if not targets:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',0,0,"
                    "'no targets (no surface snapshot yet, and webscan.targets empty)')")
        con.commit()
        print("webscan: no targets — skipped")
        return 0
    cmd = _cmd(bin, targets)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',0,0,'timed out')")
        con.commit(); print("webscan: timed out"); return 0
    rows = parse((p.stdout or "").splitlines())
    new = 0
    alerts = []
    for f in rows:
        cur = con.execute("insert or ignore into web_findings(ts,host,template,name,severity,matched,curl,seen) "
                          "values(datetime('now'),?,?,?,?,?,?,0)", (f["host"], f["template"], f["name"],
                                                                    f["severity"], f["matched"], f["curl"]))
        if cur.rowcount == 0:                       # already known: bump seen, don't re-alert
            con.execute("update web_findings set seen=seen+1, ts=datetime('now') where host=? and template=?",
                        (f["host"], f["template"]))
            continue
        new += 1
        if f["severity"] in ("critical", "high"):
            alerts.append(f"🕸 **{f['name']}** — `{f['template']}` on {f['host']}\n   {f['matched']}")
    con.commit()                                    # commit BEFORE any notify call
    if alerts:
        notify.send("🌐 **Web app findings** (app-layer, detect-only — fix in code)\n" + "\n".join(alerts[:10])
                    + (f"\n… +{len(alerts) - 10} more → warden · Attack surface" if len(alerts) > 10 else ""))
    con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',?,?,?)",
                (len(rows), new, f"{new} new finding(s) across {len(targets)} target(s)"))
    con.commit()
    print(f"webscan: {new} new / {len(rows)} total findings, {len(targets)} target(s)")
    return 0


def main():
    if "--list" in sys.argv:
        for r in db().execute("select ts,host,severity,name,template from web_findings order by id desc limit 50"):
            print(" | ".join(x or "" for x in r))
        return 0
    return scan()


if __name__ == "__main__":
    sys.exit(main())
