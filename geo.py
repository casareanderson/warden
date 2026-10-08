#!/usr/bin/env python3
"""geo.py — offline IP → country for warden (no API calls per lookup, no account).

Data: DB-IP "IP to Country Lite" (CC BY 4.0, https://db-ip.com — attribution is
shown on the dashboard footer, which the licence requires). Refreshed monthly
by `geo.py update`; lookups read data/geo.db in read-only mode.

  geo.py update        download this month's CSV into data/geo.db (no-op if current)
  geo.py <ip> [...]    look addresses up
"""
import csv
import gzip
import io
import ipaddress
import os
import sqlite3
import sys
import threading
import urllib.request
from datetime import date

GEO_DB = os.environ.get("WARDEN_GEO_DB") or os.path.join(
    os.environ.get("WARDEN_DATA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"), "geo.db")
URL = "https://download.db-ip.com/free/dbip-country-lite-{m}.csv.gz"


def _key(ip):
    """Fixed-width hex so IPv4 and IPv6 sort correctly as TEXT in one table."""
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return f"{a.version}:{int(a):032x}"


def update(force=False):
    month = date.today().strftime("%Y-%m")
    if os.path.exists(GEO_DB) and not force:
        try:
            con = sqlite3.connect(f"file:{GEO_DB}?mode=ro", uri=True)
            have = con.execute("select v from meta where k='month'").fetchone()
            con.close()
            if have and have[0] == month:
                print(f"geo: already {month}")
                return 0
        except sqlite3.Error:
            pass
    raw = None
    for m in (month, (date.today().replace(day=1) - __import__("datetime").timedelta(days=1)).strftime("%Y-%m")):
        try:
            req = urllib.request.Request(URL.format(m=m), headers={"User-Agent": "warden-geo/1"})
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
            month = m
            break
        except Exception as e:  # noqa: BLE001 — first-of-month the new file may not exist yet
            print(f"geo: {m} unavailable ({e})")
    if raw is None:
        return 1
    tmp = GEO_DB + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute("create table geo(start text primary key, stop text, cc text)")
    con.execute("create table meta(k text primary key, v text)")
    rows = 0
    batch = []
    for start, stop, cc in csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(raw)), "utf-8")):
        batch.append((_key(start), _key(stop), cc))
        if len(batch) >= 50000:
            con.executemany("insert or replace into geo values(?,?,?)", batch); rows += len(batch); batch = []
    con.executemany("insert or replace into geo values(?,?,?)", batch); rows += len(batch)
    con.execute("insert into meta values('month',?)", (month,))
    con.commit(); con.close()
    if rows < 100000:                       # a truncated download must not replace a good table
        print(f"geo: only {rows} rows — refusing to install")
        os.remove(tmp)
        return 1
    os.replace(tmp, GEO_DB)
    print(f"geo: installed {month}, {rows} ranges")
    return 0


class Geo:
    """Cached lookups. Private / unparseable / unknown → '' (never a guess)."""

    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()   # one sqlite connection shared by the UI's request threads
        try:
            self.con = sqlite3.connect(f"file:{GEO_DB}?mode=ro", uri=True, check_same_thread=False)
        except sqlite3.Error:
            self.con = None

    def cc(self, ip):
        if not ip or self.con is None:
            return ""
        if ip in self.cache:
            return self.cache[ip]
        out = ""
        try:
            a = ipaddress.ip_address(ip)
            if a.is_global:
                k = _key(ip)
                with self.lock:
                    r = self.con.execute("select stop, cc from geo where start <= ? order by start desc limit 1",
                                         (k,)).fetchone()
                if r and k <= r[0] and r[1] != "ZZ":
                    out = r[1]
        except (ValueError, sqlite3.Error):
            pass
        self.cache[ip] = out
        return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "update":
        sys.exit(update("--force" in sys.argv))
    g = Geo()
    for ip in sys.argv[1:]:
        print(ip, g.cc(ip) or "-")
