#!/usr/bin/env python3
"""harden.py — weekly hardening audit (Lynis) across the estate for warden (built 2026-10-07). No LLM.

Owner's choice 2026-10-07: "temporary Lynis run". Per box: copy the VERIFIED Lynis tarball to /tmp, run
`lynis audit system --quick` (read-only audit), read its report file, delete everything — nothing stays installed.

  harden.py              audit every box (timer: Sun 05:00)
  harden.py <target>     audit one box (ct:101, node:10.0.0.2, host:10.0.0.6)
  harden.py --fetch      download + verify Lynis (sha256 pinned below, from cisofy.com/downloads/lynis)
  harden.py --list       scores

Alerts (wlib.notify) when a box's hardening index drops ≥5 points or a NEW warning appears.
"""
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
VERSION = "3.1.7"
SHA256 = "b5314a07fd85fa3ffc7da57b508f0108ec3280d84e4af823f805d95cbbc2428c"   # cisofy.com/downloads/lynis, 2026-10-07
URL = f"https://downloads.cisofy.com/lynis/lynis-{VERSION}.tar.gz"
TGZ = str(config.DATA / f"lynis-{VERSION}.tar.gz")
REMOTE = "/tmp/warden-lynis"
AUDITED = ("node", "ct", "host", "local")
RUN = (f"set -e; rm -rf {REMOTE}; mkdir -p {REMOTE}; tar xzf {REMOTE}.tgz -C {REMOTE} --strip-components=1 "
       f"--no-same-owner; chown -R 0:0 {REMOTE}; cd {REMOTE}; "
       f"./lynis audit system --quick --no-colors --quiet --report-file {REMOTE}.dat --logfile /dev/null "
       f">/dev/null 2>&1 || true; cat {REMOTE}.dat; rm -rf {REMOTE} {REMOTE}.tgz {REMOTE}.dat")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.executescript("""
      create table if not exists harden(target text primary key, name text, ts text, idx integer, tests integer,
        warnings text, suggestions text, status text, note text, prev_idx integer);
    """)
    return con


def fetch():
    if os.path.exists(TGZ) and hashlib.sha256(open(TGZ, "rb").read()).hexdigest() == SHA256:
        return TGZ
    r = requests.get(URL, timeout=120)
    r.raise_for_status()
    got = hashlib.sha256(r.content).hexdigest()
    if got != SHA256:
        raise RuntimeError(f"Lynis checksum MISMATCH ({got[:16]}…) — refusing to run it anywhere")
    open(TGZ, "wb").write(r.content)
    return TGZ


def push(t):
    """Get the tarball to {REMOTE}.tgz on the box."""
    if t["kind"] == "local":
        import shutil  # noqa: PLC0415
        shutil.copy(TGZ, f"{REMOTE}.tgz")
        return
    ok, err = hosts.push(t, TGZ, f"{REMOTE}.tgz", mode="644")
    if not ok:
        raise RuntimeError(f"copy failed: {err[:150]}")


def audit(t):
    push(t)
    # Lynis needs root: plain hosts go through sudo (the host's sudo_secret, over stdin)
    rc, out, _ = hosts.remote(t, RUN, timeout=1800, root=t["kind"] in ("host", "local"))
    rep = {}
    warn, sugg = [], []
    for l in (out or "").splitlines():
        k, _, v = l.partition("=")
        if k == "warning[]":
            f = v.split("|"); warn.append({"id": f[0], "text": f[1] if len(f) > 1 else ""})
        elif k == "suggestion[]":
            f = v.split("|"); sugg.append({"id": f[0], "text": f[1] if len(f) > 1 else "",
                                           "detail": f[2] if len(f) > 2 and f[2] != "-" else ""})
        elif k in ("hardening_index", "lynis_tests_done"):
            rep[k] = v
    if "hardening_index" not in rep:
        raise RuntimeError("no report produced (lynis did not run?)")
    return int(rep["hardening_index"]), int(rep.get("lynis_tests_done") or 0), warn, sugg


def main():
    a = sys.argv[1:]
    con = db()
    if a and a[0] == "--list":
        for r in con.execute("select target,name,idx,prev_idx,tests,status,ts,json_array_length(warnings),"
                             "json_array_length(suggestions) from harden order by idx"):
            print(r)
        return 0
    fetch()
    if a and a[0] == "--fetch":
        print("lynis verified:", TGZ); return 0
    only = a[0] if a else None
    loud = []
    for t in hosts.targets():
        if t["kind"] not in AUDITED or (only and t["target"] != only):
            continue
        prev = con.execute("select idx, warnings from harden where target=?", (t["target"],)).fetchone()
        try:
            idx, tests, warn, sugg = audit(t)
        except Exception as e:  # noqa: BLE001
            con.execute("insert into harden(target,name,ts,status,note) values(?,?,?,?,?) on conflict(target) do update "
                        "set ts=excluded.ts, status='error', note=excluded.note", (t["target"], t["name"], now(), "error",
                                                                                   str(e)[:200]))
            con.commit(); print(f"{t['target']}: ERROR {e}"); continue
        con.execute("insert or replace into harden(target,name,ts,idx,tests,warnings,suggestions,status,note,prev_idx) "
                    "values(?,?,?,?,?,?,?,?,?,?)", (t["target"], t["name"], now(), idx, tests, json.dumps(warn),
                                                    json.dumps(sugg), "ok", "", prev[0] if prev else None))
        con.commit()
        print(f"{t['target']:<22} {t['name']:<14} index {idx}  tests {tests}  warnings {len(warn)}  suggestions {len(sugg)}")
        if prev and prev[0] is not None:
            old = {w["id"] for w in json.loads(prev[1] or "[]")}
            new = [w for w in warn if w["id"] not in old]
            if idx <= prev[0] - 5 or new:
                loud.append(f"**{t['name']}** (`{t['target']}`): hardening {prev[0]} → {idx}" +
                            ("; new warnings: " + "; ".join(f"{w['id']} {w['text']}" for w in new[:4]) if new else ""))
    if loud and not notify.send(("🛡️ **Hardening (Lynis) changed**\n" + "\n".join(loud[:12]))[:1990]):
        print("notify failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
