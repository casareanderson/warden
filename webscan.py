#!/usr/bin/env python3
"""webscan.py — app-layer web vulnerability scan (DAST) for the estate's own sites (built 2026-10-22). No LLM.

warden already scans the PACKAGES behind a public site (vulnscan.py → OSV.dev) and the EXPOSURE/config (intel.py).
This fills the gap the package scan can't: the web application itself. It runs TWO layers, both detect-only:

  1. built-in checks (always, no install): security headers (HSTS/X-Frame-Options/X-Content-Type-Options), exposed
     sensitive files (/.env, /.git/config, /.aws/credentials, wp-config backups…), and exposed admin panels
     (Tomcat manager, phpMyAdmin, Spring actuator, Jenkins, Grafana…). Content-signature matched, so a single-page
     app returning its 200 shell for every path is NOT a false positive.
  2. nuclei (optional, if installed): the full ProjectDiscovery template library on top.

    webscan.py            run one scan (timer: daily 04:10, after the 03:30 vuln scan)
    webscan.py --list     recent findings

warden.yml:
    webscan:
      nuclei: ""                 # path to nuclei; "" = look on PATH. Built-in checks run with or without it.
      targets: []                # extra URLs (https://host[:port]) on top of the public names warden already knows
      auto_targets: true         # also scan the public names in warden's attack-surface snapshot
      severity: medium,high,critical   # record/alert at or above this
      rate_limit: 10             # requests per second (be gentle with your own sites)

Hard rules:
  - Only the estate's own targets are ever scanned (public names from the surface snapshot + webscan.targets).
  - Detect-only. No finding here is ever auto-fixed — an app bug is fixed in code, not by `apt`, so it reports and
    you fix it. There is deliberately no patch path.
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
UA = "warden-webscan/1.0"

# (path, name, severity, content-signature regex or None for "non-HTML content")
SENSITIVE = [
    ("/.env", "Exposed .env file", "high", r"(?im)^\s*[A-Za-z_][A-Za-z0-9_]*="),
    ("/.git/config", "Exposed git repository", "high", r"(?i)\[(core|remote)\]"),
    ("/.git/HEAD", "Exposed git repository", "high", r"(?i)^\s*ref:\s*refs/"),
    ("/.aws/credentials", "Exposed AWS credentials", "critical", r"(?i)aws_access_key_id"),
    ("/wp-config.php.bak", "WordPress config backup", "high", r"(?i)(DB_PASSWORD|DB_NAME|DB_USER)"),
    ("/config.json", "Exposed config.json", "medium", r"^\s*[\{\[]"),
    ("/.DS_Store", "Exposed .DS_Store", "low", None),
    ("/server-status", "Apache server-status", "medium", r"(?i)(apache server status|server version)"),
]
PANELS = [
    ("/manager/html", "Apache Tomcat manager", "high", r"(?i)apache tomcat"),
    ("/phpmyadmin/", "phpMyAdmin", "high", r"(?i)phpmyadmin"),
    ("/actuator/env", "Spring Boot actuator (env)", "critical", r"(?i)(java\.home|spring\.datasource|user\.home|os\.arch)"),
    ("/actuator", "Spring Boot actuator", "high", r"(?i)spring boot"),
    ("/jenkins/login", "Jenkins", "medium", r"(?i)jenkins"),
    ("/grafana/login", "Grafana", "low", r"(?i)grafana"),
    ("/solr/", "Apache Solr", "medium", r"(?i)apache solr"),
    ("/wp-login.php", "WordPress login", "low", r"(?i)wordpress"),
]
# (header name, finding name, severity) — HSTS matters most; CSP/Referrer-Policy are near-universally absent so left out.
HEADERS = [
    ("strict-transport-security", "Missing HSTS", "medium"),
    ("x-frame-options", "Missing X-Frame-Options", "low"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
]


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
            c = sqlite3.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=10)
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


# ── nuclei layer (optional) ─────────────────────────────────────────────────
def _cmd(bin, targets):
    return [bin, "-jsonl", "-silent", "-no-color",
            "-severity", config.get("webscan.severity") or "medium,high,critical",
            "-rate-limit", str(int(config.get("webscan.rate_limit") or 10)),
            "-timeout", "15", "-retries", "1",
            "-tags", config.get("webscan.tags") or "cves,exposures,misconfig,technologies"] + \
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


# ── built-in layer (always, no install) ─────────────────────────────────────
def _session():
    import requests  # noqa: PLC0415
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def _get(s, url, redirects=True):
    import requests  # noqa: PLC0415
    try:
        return s.get(url, timeout=20, allow_redirects=redirects)
    except requests.RequestException:
        return None


def _headers(s, base):
    r = _get(s, base)
    if r is None:
        return []
    have = {k.lower() for k in r.headers}
    return [{"host": base, "template": "builtin:headers:" + h, "name": name, "severity": sev,
             "matched": base, "curl": f"curl -sI {base}"}
            for h, name, sev in HEADERS if h not in have]


def _paths(s, base, checks, kind):
    out = []
    for path, name, sev, sig in checks:
        url = base + path
        r = _get(s, url, redirects=False)
        if r is None or r.status_code != 200:
            continue
        ct = (r.headers.get("content-type") or "").lower()
        if sig:
            if not re.search(sig, r.text[:4000]):
                continue                          # an SPA's 200 shell is not the file/panel it pretends to be
        elif "text/html" in ct:
            continue
        out.append({"host": base, "template": f"builtin:{kind}:{path.strip('/')}", "name": name, "severity": sev,
                    "matched": url, "curl": f"curl -s {url}"})
    return out


def builtin_checks(targets):
    s = _session()
    out = []
    delay = max(0.05, 1.0 / max(1, int(config.get("webscan.rate_limit") or 10)))
    for t in targets:
        out += _headers(s, t)
        out += _paths(s, t, SENSITIVE, "file")
        out += _paths(s, t, PANELS, "panel")
        time.sleep(delay)
    return out


def _store(con, findings):
    new = 0
    alerts = []
    for f in findings:
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
    return new, alerts


def scan():
    con = db()
    targets = _targets()
    if not targets:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',0,0,"
                    "'no targets (no surface snapshot yet, and webscan.targets empty)')")
        con.commit()
        print("webscan: no targets — skipped")
        return 0
    findings = builtin_checks(targets)
    layers = ["built-in"]
    bin = nuclei_bin()
    if bin:
        try:
            p = subprocess.run(_cmd(bin, targets), capture_output=True, text=True, timeout=3600)
            findings += parse((p.stdout or "").splitlines())
            layers.append("nuclei")
        except subprocess.TimeoutExpired:
            con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',0,0,'nuclei timed out')")
            con.commit()
    new, alerts = _store(con, findings)
    if alerts:
        notify.send("🌐 **Web app findings** (app-layer, detect-only — fix in code)\n" + "\n".join(alerts[:10])
                    + (f"\n… +{len(alerts) - 10} more → warden · Attack surface" if len(alerts) > 10 else ""))
    con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'webscan',?,?,?)",
                (len(findings), new, f"{new} new finding(s) across {len(targets)} target(s) · {'+'.join(layers)}"))
    con.commit()
    print(f"webscan: {new} new / {len(findings)} total findings, {len(targets)} target(s) · {'+'.join(layers)}")
    return 0


def main():
    if "--list" in sys.argv:
        for r in db().execute("select ts,host,severity,name,template from web_findings order by id desc limit 50"):
            print(" | ".join(x or "" for x in r))
        return 0
    return scan()


if __name__ == "__main__":
    sys.exit(main())
