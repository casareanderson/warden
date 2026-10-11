#!/usr/bin/env python3
"""beszel-snapshot — read Beszel's hub DB READ-ONLY and write a small JSON snapshot for dashboards.

Beszel stays the collector (hub + agents unchanged). Dashboards (e.g. warden's Host health card) read
the snapshot file instead of the hub, so neither needs Beszel credentials or access to its database.

  beszel-snapshot.py [--db PATH] [--out PATH] [--stale-s N] [--print]

Default DB /opt/beszel/beszel_data/data.db (pass --db for other installs), default out /var/lib/beszel-snapshot/hosts.json (written atomically).
Fields taken from Beszel's own records: systems.info (live), system_details (static), system_stats type '20m' (24 h
sparklines) and type '1m' (latest temperatures / network), alerts (thresholds + triggered flag), alerts_history (recent).
"""
import argparse, datetime as dt, json, os, sqlite3, sys, tempfile

DB = "/opt/beszel/beszel_data/data.db"   # hub install-script default; pass --db for others
OUT = "/var/lib/beszel-snapshot/hosts.json"
SPARK_POINTS = 72          # 24 h of 20-minute records
HISTORY = 20


def ts(s):
    """Beszel/PocketBase timestamps look like '2026-10-11 10:15:31.981Z'."""
    if not s:
        return None
    try:
        return dt.datetime.strptime(s.replace("Z", ""), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return dt.datetime.strptime(s.replace("Z", "")[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)


def iso(t):
    return t.isoformat().replace("+00:00", "Z") if t else None


def jload(s):
    try:
        return json.loads(s) if s else {}
    except ValueError:
        return {}


def snapshot(db_path, stale_s=180, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    db.row_factory = sqlite3.Row
    details = {r["system"]: dict(r) for r in db.execute("select * from system_details")}
    alerts = {}
    for r in db.execute("select system, name, value, triggered from alerts"):
        alerts.setdefault(r["system"], []).append({"name": r["name"], "value": r["value"], "triggered": bool(r["triggered"])})
    since = (now - dt.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    spark = {}
    for r in db.execute("select system, created, stats from system_stats where type='20m' and created >= ? order by created",
                        (since,)):
        s = jload(r["stats"])
        spark.setdefault(r["system"], []).append([s.get("cpu"), s.get("mp"), s.get("dp")])
    latest = {}
    for (sid,) in db.execute("select id from systems").fetchall():
        r = db.execute("select stats from system_stats where type='1m' and system=? order by created desc limit 1",
                       (sid,)).fetchone()
        if r:
            latest[sid] = jload(r["stats"])
    names = {}
    hosts = []
    for r in db.execute("select id, name, host, status, updated, info from systems order by name collate nocase"):
        names[r["id"]] = r["name"]
        info = jload(r["info"])
        d = details.get(r["id"], {})
        last = ts(r["updated"])
        age = (now - last).total_seconds() if last else None
        temps = (latest.get(r["id"]) or {}).get("t") or {}
        al = alerts.get(r["id"], [])
        hot = sorted({a["name"] for a in al if a["triggered"]})
        stale = r["status"] != "up" or age is None or age > stale_s
        sv = info.get("sv") or []
        hosts.append({
            "name": r["name"], "status": r["status"], "stale": stale, "last_seen": iso(last),
            "age_s": None if age is None else int(age),
            "cpu": info.get("cpu"), "mem_pct": info.get("mp"), "disk_pct": info.get("dp"),
            "temp_c": info.get("dt"), "temp_max_c": max(temps.values()) if temps else None,
            "load": info.get("la"), "net_bps": info.get("bb"), "uptime_s": info.get("u"),
            "agent": info.get("v"), "services": sv[0] if len(sv) > 0 else None,
            "services_failed": sv[1] if len(sv) > 1 else None,
            "os": d.get("os_name"), "cpu_model": d.get("cpu"), "cores": d.get("cores"), "threads": d.get("threads"),
            "mem_bytes": d.get("memory"), "kernel": d.get("kernel"),
            "thresholds": {a["name"]: a["value"] for a in al},
            "alerts": hot, "spark": spark.get(r["id"], [])[-SPARK_POINTS:],
        })
    history = []
    for r in db.execute("select system, name, value, created, resolved from alerts_history order by created desc limit ?",
                        (HISTORY,)):
        if r["system"] not in names:
            continue
        history.append({"host": names[r["system"]], "alert": r["name"], "value": r["value"],
                        "at": iso(ts(r["created"])), "resolved": iso(ts(r["resolved"])) if r["resolved"] else None})
    db.close()
    up = sum(1 for h in hosts if not h["stale"])
    return {"generated": iso(now), "source": "beszel", "hosts": hosts, "history": history,
            "summary": {"total": len(hosts), "up": up, "stale_or_down": len(hosts) - up,
                        "alerting": sorted(h["name"] for h in hosts if h["alerts"] and not h["stale"])}}


def write_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".hosts.")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--stale-s", type=int, default=180)
    ap.add_argument("--print", action="store_true")
    a = ap.parse_args(argv)
    snap = snapshot(a.db, a.stale_s)
    if a.print:
        print(json.dumps(snap, indent=1)[:4000])
    else:
        write_atomic(a.out, snap)
        print(f"ok {snap['summary']}")


if __name__ == "__main__":
    sys.exit(main())
