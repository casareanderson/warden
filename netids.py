#!/usr/bin/env python3
"""netids.py — pull Suricata alerts into warden (built 2026-10-07). No LLM.

Reference setup: Suricata 7 (Debian pkg) running ON a Proxmox node, af-packet on the bridge (vmbr0), so it
sees every packet to/from the guests on that bridge and the node itself. ET Open rules refreshed daily by
cron (`suricata-update`). Disable `group:emerging-info.rules` in /etc/suricata/disable.conf — on day one
100% of alerts were ET INFO "Discord domain" = our own bot. Cap it with a systemd drop-in (we use 1.5 GB /
150% CPU).

Config (warden.yml):
  ids.suricata_host   where Suricata runs: `root@host` / `host` (SSH as root) or `local`. Unset → skip.
  ids.eve_path        its eve.json (default /var/log/suricata/eve.json)
  ids.label           optional label for alerts, e.g. "pve2 vmbr0"

  netids.py           pull new eve.json lines (byte watermark; handles rotation), store, alert (timer: 5 min)
  netids.py --test    show the last 10 stored alerts

Alert channel (wlib.notify): severity 1, or severity 2 in malware/C2/exploit/attack-response categories;
deduped per (signature, source) for 6 h.
"""
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from geo import Geo  # noqa: E402
from wlib import config, notify  # noqa: E402

DB = config.DB


def EVE():  # noqa: N802
    return config.get("ids.eve_path") or "/var/log/suricata/eve.json"


def SSH():  # noqa: N802
    """argv prefix that runs a shell command where Suricata lives ([] = locally)."""
    h = str(config.get("ids.suricata_host") or "")
    if h in ("local", "localhost"):
        return ["sh", "-c"]
    tgt = h if "@" in h else f"root@{h}"
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", tgt]


MAX_BYTES = 20_000_000
LOUD_CATS = ("trojan", "malware", "command and control", "exploit", "attack response", "attempted-admin",
             "successful", "shellcode", "coin", "ransom")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.executescript("""
      create table if not exists watermarks(source text primary key, pos text);
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer,
        parsed integer, note text);
      create table if not exists ids_alerts(
        id integer primary key, ts text, sid integer, signature text, severity integer, category text,
        src text, sport integer, dst text, dport integer, proto text, app text, cc text, community_id text,
        notified integer default 0);
      create index if not exists ia_ts on ids_alerts(ts);
    """)
    return con


def pull(con):
    wm = con.execute("select pos from watermarks where source='suricata'").fetchone()
    inode, off = (wm[0].split(":") + ["0"])[:2] if wm else ("", "0")
    st = subprocess.run(SSH() + [f"stat -c %i:%s {EVE()}"], capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=30).stdout.strip()
    if not st:
        raise RuntimeError(f"eve.json not readable on {config.get('ids.suricata_host')}")
    cur_inode, size = st.split(":")
    off = int(off) if cur_inode == inode and int(off) <= int(size) else 0       # rotated/truncated → start over
    n = min(int(size) - off, MAX_BYTES)
    data = subprocess.run(SSH() + [f"tail -c +{off + 1} {EVE()} | head -c {n}"], capture_output=True, stdin=subprocess.DEVNULL, timeout=120).stdout
    last_nl = data.rfind(b"\n")
    data = data[:last_nl + 1] if last_nl >= 0 else b""
    con.execute("insert or replace into watermarks(source,pos) values('suricata',?)", (f"{cur_inode}:{off + len(data)}",))
    return [l for l in data.decode("utf-8", "replace").splitlines() if l]


def main():
    con = db()
    if "--test" in sys.argv:
        for r in con.execute("select ts,severity,signature,src,dst,dport,cc from ids_alerts order by id desc limit 10"):
            print(r)
        return 0
    if not config.get("ids.suricata_host"):
        print("suricata: ids.suricata_host not set — network IDS is optional, nothing to do")
        return 0
    geo = Geo()
    try:
        lines = pull(con)
    except Exception as e:  # noqa: BLE001
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'suricata',0,0,?)",
                    (f"BLIND: {e}"[:200],)); con.commit()
        print(f"suricata: {e}"); return 1
    added, loud = 0, []
    for l in lines:
        try:
            e = json.loads(l)
        except ValueError:
            continue
        if e.get("event_type") not in ("alert", "anomaly"):
            continue
        a = e.get("alert") or {}
        sig = a.get("signature") or ("anomaly: " + str((e.get("anomaly") or {}).get("event") or ""))
        sev = a.get("severity") or 3
        cat = a.get("category") or "anomaly"
        src, dst = e.get("src_ip", ""), e.get("dest_ip", "")
        outside = src if not src.startswith(("192.168.", "10.", "100.")) else dst
        con.execute("insert into ids_alerts(ts,sid,signature,severity,category,src,sport,dst,dport,proto,app,cc,"
                    "community_id) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (e.get("timestamp", "")[:19].replace("T", " "), a.get("signature_id"), sig[:200], sev, cat[:80],
                     src, e.get("src_port"), dst, e.get("dest_port"), e.get("proto"), e.get("app_proto"),
                     geo.cc(outside), e.get("community_id")))
        added += 1
        if e["event_type"] == "alert" and (sev == 1 or (sev == 2 and any(k in cat.lower() or k in sig.lower()
                                                                           for k in LOUD_CATS))):
            dup = con.execute("select 1 from ids_alerts where sid=? and src=? and notified=1 and "
                              "ts > datetime('now','-6 hours')", (a.get("signature_id"), src)).fetchone()
            if not dup:
                con.execute("update ids_alerts set notified=1 where id=last_insert_rowid()")
                loud.append(f"sev{sev} **{sig}** — {src}:{e.get('src_port')} → {dst}:{e.get('dest_port')} "
                            f"({e.get('app_proto') or e.get('proto')}){' ' + geo.cc(outside) if geo.cc(outside) else ''}")
    con.execute("delete from ids_alerts where ts < datetime('now','-90 days')")
    con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'suricata',?,?,'ok')",
                (len(lines), added))
    con.commit()
    if loud:
        label = config.get("ids.label") or config.get("ids.suricata_host")
        if not notify.send((f"🛰️ **Suricata ({label})**\n" + "\n".join(loud[:15]))[:1990]):
            print("notify failed")
    print(f"suricata: {len(lines)} lines, {added} stored, {len(loud)} notified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
