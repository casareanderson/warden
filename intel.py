#!/usr/bin/env python3
"""intel.py — warden's outside-in view: what Cloudflare stopped, and what is exposed.

  intel.py edge       pull Cloudflare firewall events (what the EDGE blocked/challenged) → edge_events
  intel.py surface    snapshot the external attack surface → surface_snap (+ findings)
  intel.py all        both (timer: hourly)

Read-only against Cloudflare and GitHub. Writes only to warden.db. No LLM.

Config (warden.yml):
  cloudflare.zone_id / account_id        the zone, and the account (tunnel ingress; optional)
  cloudflare.token_secret                secret name of the WAF/zone token (default CF_API_TOKEN):
                                         WAF rules, zone settings and — once it has Zone Analytics:Read —
                                         firewall events. Until then the edge run records a BLIND row with
                                         the exact missing permission, so the dashboard says "needs X"
                                         instead of "quiet".
  cloudflare.dns_token_secret            secret name of a read token for DNS records + tunnel ingress
                                         (default CF_DNS_TOKEN; falls back to the WAF token)
  cloudflare.sso_portal                  host of your SSO login page (redirects to it count as "SSO on")
  cloudflare.sso_exempt                  {host: why} — public-on-purpose hosts. Findings against them are
                                         kept but shown as ACCEPTED with the reason, so the tab separates
                                         "decided" from "not looked at yet".
  estate.domain                          the zone's domain
  intel.github_owner                     OPTIONAL plug-in: list public repos that publish GitHub Pages (gh CLI)
  intel.sso_status_cmd                   OPTIONAL plug-in: a command printing JSON [{host, sso: on|off}] for
                                         your reverse proxy's sites
Absent plug-ins are skipped, not reported as errors.
"""
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, notify, secrets  # noqa: E402

DB = config.DB
CF = "https://api.cloudflare.com/client/v4"
SELF_IPS = str(config.HOME / "self-ips.txt")


def ZONE():  # noqa: N802 - read at call time so a config edit applies without a restart
    return config.get("cloudflare.zone_id", "")


def ACCOUNT():  # noqa: N802
    return config.get("cloudflare.account_id", "")


def DOMAIN():  # noqa: N802
    return config.get("estate.domain", "")


def accepted():
    return dict(config.get("cloudflare.sso_exempt") or {})


SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy")


def now():
    return datetime.now(timezone.utc)


def db():
    con = sqlite3.connect(DB, timeout=30)
    con.executescript("""
      create table if not exists watermarks(source text primary key, pos text);
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer,
        parsed integer, note text);
      create table if not exists edge_events(
        id integer primary key, ts text, ray text unique, ip text, cc text, action text,
        source text, host text, path text, ua text, rule text);
      create index if not exists ee_ts on edge_events(ts);
      create table if not exists surface_snap(id integer primary key, ts text, data text);
    """)
    return con


def run_row(con, source, lines, parsed, note):
    con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),?,?,?,?)",
                (source, lines, parsed, note))


def waf_token():
    return secrets.get(config.get("cloudflare.token_secret") or "CF_API_TOKEN")


def dns_token():
    return secrets.get(config.get("cloudflare.dns_token_secret") or "CF_DNS_TOKEN") or waf_token()


def cf_get(path, tok, **params):
    r = requests.get(CF + path, headers={"Authorization": f"Bearer {tok}"}, params=params, timeout=30)
    try:
        d = r.json()
    except ValueError:
        return False, f"HTTP {r.status_code}"
    if not d.get("success"):
        return False, (d.get("errors") or [{"message": f"HTTP {r.status_code}"}])[0].get("message")
    return True, d["result"]


# ── edge: Cloudflare firewall events ─────────────────────────────────────────
GQL = """query($z:String!,$s:Time!,$e:Time!){viewer{zones(filter:{zoneTag:$z}){
  firewallEventsAdaptive(limit:10000,filter:{datetime_gt:$s,datetime_leq:$e},orderBy:[datetime_ASC]){
    datetime rayName action source clientIP clientCountryName clientRequestHTTPHost
    clientRequestPath clientRequestQuery userAgent ruleId description}}}}"""


def edge(con):
    tok = waf_token()
    wm = con.execute("select pos from watermarks where source='cf-edge'").fetchone()
    # Free plan keeps ~24h of firewall events; never ask further back than that.
    floor = now() - timedelta(hours=23, minutes=50)
    start = max(datetime.fromisoformat(wm[0]), floor) if wm else floor
    end = now() - timedelta(minutes=2)
    r = requests.post(f"{CF}/graphql", headers={"Authorization": f"Bearer {tok}"}, timeout=60, json={
        "query": GQL, "variables": {"z": ZONE(), "s": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    "e": end.strftime("%Y-%m-%dT%H:%M:%SZ")}}).json()
    if r.get("errors"):
        msg = r["errors"][0].get("message", "")
        if "analytics.read" in msg:
            msg = "BLIND: WAF token lacks Zone Analytics:Read (add it in CF → API Tokens)"
        run_row(con, "cf-edge", 0, 0, msg[:300])
        print("edge:", msg)
        return 1
    rows = r["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    added = 0
    for e in rows:
        cur = con.execute(
            "insert or ignore into edge_events(ts,ray,ip,cc,action,source,host,path,ua,rule) "
            "values(?,?,?,?,?,?,?,?,?,?)",
            (e["datetime"].replace("T", " ").rstrip("Z"), e["rayName"], e["clientIP"], e["clientCountryName"],
             e["action"], e["source"], e["clientRequestHTTPHost"],
             (e["clientRequestPath"] or "") + (e["clientRequestQuery"] or ""), (e["userAgent"] or "")[:200],
             e.get("description") or e.get("ruleId") or ""))
        added += cur.rowcount
    con.execute("insert or replace into watermarks(source,pos) values('cf-edge',?)", (end.isoformat(),))
    con.execute("delete from edge_events where ts < datetime('now','-90 days')")
    run_row(con, "cf-edge", len(rows), added, "ok")
    print(f"edge: {len(rows)} events, {added} new")
    return 0


# ── surface: what is reachable from the internet ─────────────────────────────
def self_ips():
    try:
        return {l.split("#")[0].strip() for l in open(SELF_IPS) if l.split("#")[0].strip()}
    except OSError:
        return set()


def public_a(host):
    p = subprocess.run(["dig", "+short", "@1.1.1.1", host, "A"], capture_output=True, text=True, timeout=15)
    return [x for x in p.stdout.split() if x[0].isdigit()]


def probe(host, ips):
    """Hit the host the way the INTERNET does (public resolution), not via the LAN rewrite."""
    if not ips:
        return {"status": "no-public-A"}
    ip = ips[0]
    if ip.startswith(("10.", "192.168.", "172.16.")):
        return {"status": "private-ip"}
    p = subprocess.run(["curl", "-s", "-o", "/dev/null", "-D", "-", "-m", "15", "--resolve", f"{host}:443:{ip}",
                        "-w", "\n__CODE=%{http_code} __REDIR=%{redirect_url} __TLS=%{ssl_verify_result}",
                        f"https://{host}/"], capture_output=True, text=True, timeout=25)
    out = p.stdout
    hdrs = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip()
            for l in out.splitlines() if ":" in l and not l.startswith("__")}
    tail = out.rsplit("\n", 1)[-1]
    meta = dict(kv.split("=", 1) for kv in tail.split() if "=" in kv)
    redir = meta.get("__REDIR", "")
    return {"status": meta.get("__CODE", "000"), "tls_ok": meta.get("__TLS") == "0",
            "sso": (bool(config.get("cloudflare.sso_portal")) and config.get("cloudflare.sso_portal") in redir)
                   or meta.get("__CODE") == "401",
            "redirect": redir[:120], "server": hdrs.get("server", ""),
            "headers": {h: (h in hdrs) for h in SECURITY_HEADERS}}


# ── optional plug-ins (skipped when not configured) ──────────────────────────
def pages(snap):
    """Public repos that publish GitHub Pages — a site you forgot is still a site."""
    owner = config.get("intel.github_owner")
    if not owner:
        return
    # systemd runs this without HOME, and gh then cannot find its login — say so, don't guess
    ghenv = {**os.environ, "HOME": os.environ.get("HOME") or "/root"}
    try:
        p = subprocess.run(["gh", "repo", "list", owner, "--visibility", "public", "--limit", "200",
                            "--json", "name", "--jq", ".[].name"], capture_output=True, text=True, timeout=60, env=ghenv)
    except (OSError, subprocess.TimeoutExpired) as e:
        snap["errors"].append(f"github: {type(e).__name__}")
        return
    for name in p.stdout.split():
        q = subprocess.run(["gh", "api", f"repos/{owner}/{name}/pages", "--jq", ".html_url"],
                           capture_output=True, text=True, timeout=30, env=ghenv)
        if q.returncode == 0 and q.stdout.strip():
            snap["pages"].append({"repo": name, "url": q.stdout.strip()})
    if p.returncode != 0:
        snap["errors"].append("github: " + (p.stderr.strip().splitlines() or ["gh repo list failed"])[-1][:120])


def sso_sites(snap):
    """Reverse-proxy sites and whether SSO guards them, from a site-specific status command."""
    cmd = config.get("intel.sso_status_cmd")
    if not cmd:
        return
    try:
        snap["sso"] = json.loads(subprocess.run(cmd.split() if isinstance(cmd, str) else cmd, capture_output=True,
                                                text=True, timeout=120).stdout)
    except Exception as e:  # noqa: BLE001
        snap["sso"] = []; snap["errors"].append(f"sso: {type(e).__name__}")


def surface(con):
    snap = {"ts": now().isoformat(timespec="seconds"), "hosts": [], "waf": [], "settings": {},
            "pages": [], "findings": [], "errors": []}
    f = snap["findings"]
    mine = self_ips()

    ok, recs = cf_get(f"/zones/{ZONE()}/dns_records", dns_token(), per_page=500)
    ingress = {}
    if ACCOUNT():                       # tunnel ingress needs the account id; without it, skip quietly
        ok_t, tcfg = cf_get(f"/accounts/{ACCOUNT()}/cfd_tunnel", dns_token(), is_deleted="false")
        if ok_t:
            for t in tcfg:
                okc, c = cf_get(f"/accounts/{ACCOUNT()}/cfd_tunnel/{t['id']}/configurations", dns_token())
                if okc:
                    for i in (c.get("config") or {}).get("ingress", []):
                        if i.get("hostname"):
                            ingress.setdefault(i["hostname"], i.get("service", ""))
        else:
            snap["errors"].append(f"tunnel: {tcfg}")
    snap["ingress"] = ingress
    if not ok:
        snap["errors"].append(f"dns: {recs}")
        recs = []
    for r in sorted(recs, key=lambda r: r["name"]):
        if r["type"] not in ("A", "AAAA", "CNAME"):
            continue
        name, content = r["name"], str(r["content"])
        if content.startswith(("10.", "192.168.", "172.16.")):
            kind = "lan-only"
        elif content.endswith(".cfargotunnel.com"):
            kind = "tunnel"
        elif content.endswith("github.io"):
            kind = "github-pages"
        elif r["proxied"]:
            kind = "proxied"
        else:
            kind = "third-party" if r["type"] == "CNAME" else "direct"
        h = {"name": name, "type": r["type"], "content": content, "proxied": r["proxied"], "kind": kind,
             "origin": ingress.get(name, "")}
        if kind != "lan-only":
            h["probe"] = probe(name, public_a(name))
        snap["hosts"].append(h)

        # findings — each one names WHY it matters, so the tab is a to-do list, not a dump
        if kind == "lan-only":
            f.append({"sev": "low", "host": name, "issue": "private IP published in public DNS",
                      "why": "anyone running dig learns internal addressing; harmless but avoidable"})
        if kind == "direct" and content in mine:
            f.append({"sev": "high", "host": name, "issue": "DNS-only record points at the home WAN IP",
                      "why": "bypasses Cloudflare entirely and reveals the home address"})
        pr = h.get("probe") or {}
        if kind == "tunnel" and pr.get("status", "").startswith("2") and not pr.get("sso"):
            f.append({"sev": "med", "host": name, "issue": "public tunnel host answers without SSO",
                      "why": "the app's own login is the only door (fine for apps that can't follow SSO, check anything new)"})
        if kind in ("tunnel", "proxied") and pr.get("status", "000") != "000" and not pr.get("headers", {}).get(
                "strict-transport-security"):
            f.append({"sev": "low", "host": name, "issue": "no HSTS header",
                      "why": "a first visit can be downgraded to HTTP"})
        if kind in ("tunnel", "proxied", "github-pages") and pr.get("status") == "000":
            f.append({"sev": "med", "host": name, "issue": "public name does not answer",
                      "why": "dangling DNS → a takeover risk if the target is ever reclaimed"})
    for hn, svc in ingress.items():
        if not any(x["name"] == hn for x in snap["hosts"]):
            f.append({"sev": "med", "host": hn, "issue": "tunnel ingress with no DNS record",
                      "why": f"stale route to {svc}; remove it or it reopens the moment a record is added"})

    tok = waf_token()
    ok, rs = cf_get(f"/zones/{ZONE()}/rulesets/phases/http_request_firewall_custom/entrypoint", tok)
    if ok:
        snap["waf"] = [{"desc": r.get("description", ""), "action": r.get("action"), "enabled": r.get("enabled", True),
                        "expr": r.get("expression", "")[:300]} for r in rs.get("rules", [])]
    else:
        snap["errors"].append(f"waf: {rs}")
    for k in ("ssl", "min_tls_version", "always_use_https", "security_level", "browser_check", "tls_1_3",
              "automatic_https_rewrites"):
        okk, v = cf_get(f"/zones/{ZONE()}/settings/{k}", tok)
        snap["settings"][k] = v.get("value") if okk else None
    s = snap["settings"]
    if s.get("ssl") not in (None, "strict", "full_strict"):
        f.append({"sev": "high", "host": DOMAIN(), "issue": f"SSL mode is {s.get('ssl')}",
                  "why": "edge→origin TLS is not fully verified"})
    if s.get("min_tls_version") in ("1.0", "1.1"):
        f.append({"sev": "med", "host": DOMAIN(), "issue": f"min TLS {s.get('min_tls_version')}",
                  "why": "legacy TLS still accepted"})
    if s.get("always_use_https") == "off":
        f.append({"sev": "med", "host": DOMAIN(), "issue": "Always Use HTTPS is off", "why": "plain-HTTP requests served"})

    pages(snap)
    acc = accepted()
    for x in f:
        if x["host"] in acc and x["sev"] != "high":
            x["accepted"] = acc[x["host"]]
    sso_sites(snap)
    sev = {"high": 0, "med": 1, "low": 2}
    f.sort(key=lambda x: ("accepted" in x, sev[x["sev"]], x["host"]))
    alert_drift(con, snap)          # compare with the PREVIOUS snapshot before storing this one
    con.execute("insert into surface_snap(ts,data) values(datetime('now'),?)", (json.dumps(snap),))
    con.execute("delete from surface_snap where id not in (select id from surface_snap order by id desc limit 60)")
    run_row(con, "surface", len(snap["hosts"]), len(f), "; ".join(snap["errors"])[:300] or "ok")
    print(f"surface: {len(snap['hosts'])} names, {len(snap['pages'])} pages, {len(snap['waf'])} WAF rules, "
          f"{len(f)} findings, errors={snap['errors']}")
    return 0


# ── exposure drift: tell the owner when the outside view CHANGES ─────────────
# Two hosts once went public via the tunnel without anyone noticing; this is the alarm for that.


def exposure_diff(prev, cur):
    """Lines describing what changed. A section whose source errored in EITHER snapshot is skipped —
    an API hiccup must not read as 'everything stopped being public'."""
    out = []
    errs = " ".join((prev.get("errors") or []) + (cur.get("errors") or []))

    def pub(s):
        return {h["name"]: f"{h['kind']} → {h.get('origin') or h['content']}" for h in s.get("hosts", [])
                if h["kind"] != "lan-only"}
    if "dns" not in errs and "tunnel" not in errs:
        a, b = pub(prev), pub(cur)
        out += [f"🆕 now PUBLIC: `{n}` ({b[n]})" for n in sorted(b.keys() - a.keys())]
        out += [f"➖ no longer public: `{n}`" for n in sorted(a.keys() - b.keys())]
        out += [f"🔀 changed: `{n}` {a[n]}  ⇒  {b[n]}" for n in sorted(a.keys() & b.keys()) if a[n] != b[n]]
        ai, bi = prev.get("ingress") or {}, cur.get("ingress") or {}
        if "ingress" in prev:
            out += [f"🆕 tunnel route: `{n}` → {bi[n]}" for n in sorted(bi.keys() - ai.keys())]
            out += [f"➖ tunnel route removed: `{n}`" for n in sorted(ai.keys() - bi.keys())]
    if "github" not in errs:
        a, b = {p["url"] for p in prev.get("pages", [])}, {p["url"] for p in cur.get("pages", [])}
        out += [f"🆕 GitHub Pages site: {u}" for u in sorted(b - a)]
        out += [f"➖ GitHub Pages site gone: {u}" for u in sorted(a - b)]
    if "waf" not in errs:
        a, b = {w["desc"] for w in prev.get("waf", [])}, {w["desc"] for w in cur.get("waf", [])}
        out += [f"🛡️ WAF rule added: {d}" for d in sorted(b - a)]
        out += [f"⚠️ WAF rule REMOVED: {d}" for d in sorted(a - b)]
    if "sso" not in errs and prev.get("sso"):
        a, b = {x["host"]: x["sso"] for x in prev["sso"]}, {x["host"]: x["sso"] for x in cur.get("sso", [])}
        out += [f"{'🔓' if b[h] == 'off' else '🔒'} SSO {a[h]}→{b[h]}: `{h}`" for h in sorted(a.keys() & b.keys())
                if a[h] != b[h]]
        out += [f"🆕 Caddy site: `{h}` (SSO {b[h]})" for h in sorted(b.keys() - a.keys())]
    key = lambda f: (f["host"], f["issue"])  # noqa: E731
    old = {key(f) for f in prev.get("findings", [])}
    out += [f"❗ new {f['sev']} finding: `{f['host']}` — {f['issue']}" for f in cur.get("findings", [])
            if key(f) not in old and f["sev"] in ("high", "med") and "accepted" not in f]
    return out


def alert_drift(con, snap):
    row = con.execute("select data from surface_snap order by id desc limit 1").fetchone()
    if not row:
        return
    lines = exposure_diff(json.loads(row[0]), snap)
    if not lines:
        return
    msg = "🌐 **Exposure changed** (warden attack surface)\n" + "\n".join(lines[:25])
    print(msg)
    if not notify.send(msg[:1990]):
        print("drift alert not sent")


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    con = db()
    rc = 0
    if not ZONE():
        print("intel: cloudflare.zone_id not set — nothing to do (Cloudflare is optional)")
        con.close()
        return 0
    try:
        if what in ("edge", "all"):
            rc |= edge(con); con.commit()
        if what in ("surface", "all"):
            rc |= surface(con); con.commit()
    finally:
        con.close()
    return 0 if what == "all" else rc   # "all" from the timer: a BLIND edge must not mark the unit failed


if __name__ == "__main__":
    sys.exit(main())
