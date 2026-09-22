#!/usr/bin/env python3
"""Read-only web view of warden.

READ-ONLY BY CONSTRUCTION: opened with SQLite ro mode, no endpoint mutates
anything, and there is deliberately no "ban this IP" button — a browser control
that can block your own front door is a different risk class.

Binds to localhost; Caddy puts auth in front (same shape as trader-ui).
"""
import json, os, sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB = os.environ.get("WARDEN_DB", "/opt/warden/data/warden.db")
PORT = int(os.environ.get("WARDEN_UI_PORT", "8792"))
HOST = os.environ.get("WARDEN_UI_HOST", "127.0.0.1")
PAGE = Path(__file__).with_name("warden-ui.html")


def q(sql, args=()):
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, args)]
    finally:
        con.close()


def payload():
    return {
        "bans": q("select ts,ip,score,reasons,state,note from bans "
                  "order by id desc limit 25"),
        "top": q("select ip, sum(score) score, count(*) n, "
                 "group_concat(distinct kind) kinds from events "
                 "where ip!='' and ts > datetime('now','-24 hours') "
                 "group by ip order by score desc limit 15"),
        "recent": q("select ts,source,ip,kind,detail,score from events "
                    "order by id desc limit 40"),
        "kinds": q("select kind, count(*) n from events "
                   "where ts > datetime('now','-7 days') "
                   "group by kind order by n desc limit 12"),
        # Source health answers the question that started this project:
        # is the thing actually READING anything, or silently blind?
        "health": q("select source, max(ts) last_run, sum(lines) lines, "
                    "sum(parsed) scored from runs "
                    "where ts > datetime('now','-24 hours') group by source"),
        "unattributed": q("select count(*) n from events where ip=''"),

        # --- network side (netscan) -------------------------------------
        # The log side answers "who attacked a service". These answer
        # "what is actually on the wire", which no log can tell you.
        "net_alerts": q("select ts,kind,mac,ip,detail from net_alerts "
                        "order by id desc limit 30"),
        "net_hosts": q("select mac,ip,hostname,vendor,first_seen,last_seen,"
                       "approved from net_hosts order by "
                       "cast(replace(ip,'.','') as integer)"),
        "net_runs": q("select max(ts) last_run, sum(hosts) hosts from net_runs "
                      "where ts > datetime('now','-1 hours')"),
        # Most-exposed hosts: how many ports each one is listening on, and
        # which. Drift here is the signal — a host that gains a port has
        # started serving something it was not serving before.
        "net_ports": q("select h.ip, h.hostname, h.vendor, count(*) n, "
                       "group_concat(np.port || '/' || coalesce(np.service,'')) ports "
                       "from net_ports np join net_hosts h on h.mac = np.mac "
                       "group by h.mac order by n desc limit 20"),
        "port_count": q("select count(*) n from net_ports"),
        # Suppressed findings are shown on purpose. A filter you cannot see
        # is indistinguishable from a detector that is not working.
        "suppressed": q("select ts,kind,detail,reason from alert_suppressed "
                        "order by id desc limit 15"),
    }


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            body, ctype = PAGE.read_bytes(), "text/html; charset=utf-8"
        elif p == "/api":
            body = json.dumps(payload(), default=str).encode()
            ctype = "application/json"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
