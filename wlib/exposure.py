"""Which scanned containers and boxes the internet can reach (built 2026-10-10). No LLM.

A CVE on something nobody outside can reach waits; the same CVE behind a public hostname doesn't. This joins three
things warden already has, or can read:

  1. public hostnames, and whether a sign-in really sits in front of them: intel.py's surface snapshot (it resolves
     every DNS record the way the internet does and probes it)
  2. where each hostname goes: the tunnel origin, then the reverse proxy's upstream (Nginx Proxy Manager / NPMplus
     API, `exposure.npm`), plus hand-written routes in `exposure.extra`
  3. who listens on that upstream: vulnscan's collector records every running container's published ports, IPs,
     network aliases and listening sockets, and each box's own IPs

and writes `exposure` (one row per hostname → target) and `vulns.exposed` (the hostnames that reach that row).

warden.yml:
  exposure:
    npm: {url: https://192.168.1.10:81, user_secret: NPM_USER, pass_secret: NPM_PASSWORD, verify_tls: false}
    extra: [{host: vpn.example.com, upstream: ["192.168.1.20:443"]}]   # routes the proxy API can't show
"""
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from . import config, secrets


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _hostport(u, default_port=80):
    if "://" not in u:
        u = "http://" + u
    p = urlparse(u)
    return p.hostname, p.port or (443 if p.scheme == "https" else default_port)


def npm_hosts():
    """{hostname: (forward_host, forward_port, sso_in_config)} from the NPM/NPMplus API (cookie or bearer auth)."""
    cfg = config.get("exposure.npm") or {}
    if not cfg.get("url"):
        return {}
    s = requests.Session()
    s.verify = bool(cfg.get("verify_tls", False))
    if not s.verify:
        requests.packages.urllib3.disable_warnings()  # self-signed admin UI on the LAN
    base = cfg["url"].rstrip("/")
    r = s.post(base + "/api/tokens", timeout=20, json={"identity": secrets.get(cfg.get("user_secret") or "NPM_USER"),
                                                       "secret": secrets.get(cfg.get("pass_secret") or "NPM_PASSWORD")})
    r.raise_for_status()
    tok = (r.json() or {}).get("token")              # classic NPM returns a bearer token; NPMplus sets a cookie
    hdr = {"Authorization": f"Bearer {tok}"} if tok else {}
    out = {}
    for h in s.get(base + "/api/nginx/proxy-hosts", headers=hdr, timeout=20).json():
        if not h.get("enabled"):
            continue
        adv = (h.get("advanced_config") or "").lower()
        sso = bool(h.get("access_list_id")) or "auth_request" in adv or "authelia" in adv or "authentik" in adv
        for name in h.get("domain_names") or []:
            out[name.lower()] = (h["forward_host"], int(h["forward_port"]), sso)
    return out


def refresh(con):
    con.execute("""create table if not exists exposure(host text, upstream text, target text, image text,
                   container text, sso integer, via text, ts text)""")
    snap = con.execute("select data from surface_snap order by id desc limit 1").fetchone() \
        if con.execute("select 1 from sqlite_master where name='surface_snap'").fetchone() else None
    public = {}
    for h in (json.loads(snap[0]).get("hosts") if snap else []) or []:
        public[h["name"].lower()] = h
    npm = npm_hosts()
    extra = {}
    for e in config.get("exposure.extra") or []:
        if e.get("host"):
            u = e.get("upstream") or []
            extra.setdefault(e["host"].lower(), []).extend([u] if isinstance(u, str) else u)

    targets = {r[0]: (r[1], set((r[2] or "").split())) for r in con.execute("select target, kind, ips from vuln_targets")}
    ports = [dict(zip(("target", "container", "image", "hostnet", "published", "ips", "aliases", "listen"), r))
             for r in con.execute("select * from img_ports")] \
        if con.execute("select 1 from sqlite_master where name='img_ports'").fetchone() else []

    def who(host, port):
        """[(target, image, container)] listening on host:port. Containers first; a box only if no container is."""
        hits = []
        for p in ports:
            hostips = targets.get(p["target"], ("", set()))[1]
            listen, pub = json.loads(p["listen"]), json.loads(p["published"])
            on_host = host in hostips and ((p["hostnet"] and port in listen) or port in pub)
            direct = (host in json.loads(p["ips"]) or host in json.loads(p["aliases"]) or host == p["container"]) \
                and port in listen
            if on_host or direct:
                hits.append((p["target"], p["image"], p["container"]))
        if not hits:
            hits = [(t, "", "") for t, (kind, ips) in targets.items() if host in ips and kind in ("ct", "node", "host",
                                                                                                  "local")]
        return hits

    rows = []
    for name, h in public.items():
        origin = h.get("origin") or ""
        if not origin and h.get("type") not in ("A", "AAAA"):
            continue                                      # Pages, Workers, mail…: no origin in this estate
        sso = int(bool((h.get("probe") or {}).get("sso")))
        hops = []
        if origin:
            o_host, o_port = _hostport(origin)
            hops.append(("origin", o_host, o_port))       # whatever terminates the tunnel is itself exposed
        up = npm.get(name)
        if up:
            hops.append(("proxy", up[0], up[1]))
            sso = sso or int(up[2])
        for u in extra.get(name, []):
            e_host, e_port = _hostport(u, 443)
            hops.append(("extra", e_host, e_port))
        for via, host, port in hops:
            for tgt, img, ctr in who(host, port):
                rows.append((name, f"{host}:{port}", tgt, img, ctr, sso, via, _now()))
    con.execute("delete from exposure")
    con.executemany("insert into exposure values(?,?,?,?,?,?,?,?)", rows)

    con.execute("update vulns set exposed=null")
    reach = {}
    for name, up, tgt, img, ctr, sso, via, ts in rows:
        reach.setdefault((tgt, img), set()).add(name + ("" if not sso else " (sign-in)"))
    for (tgt, img), names in reach.items():
        con.execute("update vulns set exposed=? where target=? and image=?", (", ".join(sorted(names)), tgt, img))
    con.execute("update vuln_targets set n_public=(select count(distinct vid) from vulns v where "
                "v.target=vuln_targets.target and v.exposed is not null and (v.fixed!='' or v.kev=1))")
    con.commit()
    open_ = sum(1 for r in rows if not r[5])
    return (f"{len(public)} public names, {len(npm)} proxy routes → {len(rows)} reachable services "
            f"({open_} with no sign-in in front)")
