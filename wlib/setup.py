"""Setup checks — ASK THE RUNNING SYSTEM, never describe it.

A key that stopped working shows as missing, not ticked. Ordered by what blocks
what: config → database → notifications → hosts → scanners → integrations → API.
Used by `warden-setup check`, the dashboard's Settings tab and /api/v1/setup.
"""
import os
import shutil
import sqlite3
import time

from . import config, hosts, secrets


def _ago_h(ts):
    try:
        import calendar  # noqa: PLC0415 - stored timestamps are UTC; mktime would read them as local time
        return (time.time() - calendar.timegm(time.strptime(ts[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))) / 3600
    except (TypeError, ValueError):
        return None


def _last_runs():
    try:
        con = sqlite3.connect(f"file:{config.DB}?mode=ro", uri=True, timeout=5)
        rows = con.execute("select source, max(ts) from runs group by source").fetchall()
        con.close()
        return dict(rows)
    except sqlite3.Error:
        return {}


def checks(probe_hosts=False):
    out = []

    def add(cid, title, ok, detail="", fix="", optional=False):
        out.append({"id": cid, "title": title, "ok": bool(ok), "detail": detail, "fix": fix, "optional": optional})

    add("config", "Config file", config.CONF.exists(), str(config.CONF),
        "run `warden-setup init` (or copy warden.yml.example to warden.yml)")
    try:
        import yaml  # noqa: F401, PLC0415
        add("yaml", "PyYAML installed", True)
    except ImportError:
        add("yaml", "PyYAML installed", False, "", "apt install python3-yaml")
    try:
        config.DATA.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(config.DB, timeout=5)
        con.execute("create table if not exists _probe(x)")
        con.execute("drop table _probe")
        con.close()
        add("db", "Database writable", True, config.DB)
    except (sqlite3.Error, OSError) as e:
        add("db", "Database writable", False, f"{config.DB}: {e}", "check the data directory's owner/permissions")

    runs = _last_runs()
    fresh = {s: _ago_h(t) for s, t in runs.items()}
    stale = [s for s, h in fresh.items() if h is None or h > 26]
    add("collectors", "Collectors ran in the last day", runs and not stale,
        ", ".join(f"{s} {round(h, 1)} h ago" for s, h in fresh.items() if h is not None) or "no runs recorded yet",
        "install and start the timers: warden-setup units --install" if not runs else
        f"stale: {', '.join(stale)} — check `journalctl -u <unit>`")

    b = (config.get("notify.backend") or "none").lower()
    need = {"discord": config.get("notify.token_secret") or "DISCORD_BOT_TOKEN",
            "webhook": config.get("notify.webhook_secret") or "ALERT_WEBHOOK"}.get(b)
    if b == "none":
        add("notify", "Alerts go somewhere", False, "notify.backend is none — alerts only reach the log",
            "set notify.backend to discord, webhook or ntfy", optional=True)
    elif need:
        extra = "" if b != "discord" or (config.get("notify.channel") and config.get("notify.owner_id")) else \
            " — also set notify.channel and notify.owner_id"
        add("notify", f"Alerts via {b}", secrets.have(need) and not extra, f"secret {need}{extra}",
            f"set {need} in the environment or data/secrets.env")
    else:
        add("notify", f"Alerts via {b}", bool(config.get("notify.ntfy_url")), config.get("notify.ntfy_url") or "",
            "set notify.ntfy_url")

    declared = hosts.declared()
    add("hosts", "Machines declared", bool(declared), f"{len(declared)} in warden.yml",
        "add your machines under `hosts:` (or `warden-setup add-host`)", optional=True)
    if probe_hosts:
        for t in hosts.targets(discover=False):
            if t["kind"] in ("node", "host", "local", "images") and not t.get("vmid"):
                ok, err = hosts.check(t)
                add(f"reach:{t['target']}", f"Reach {t['name']}", ok, t["target"] + (f" — {err}" if err else ""),
                    "check SSH keys: ssh-copy-id " + (t.get("ssh") or ""))

    trivy = config.get("vuln.trivy")
    add("trivy", "Vulnerability scanner (trivy)", bool(trivy and os.path.exists(trivy)), trivy or "",
        "install a checksum-verified trivy release (never the 0.69.4–0.69.6 builds)", optional=True)
    add("nmap", "LAN scanner (nmap)", bool(shutil.which("nmap")), "", "apt install nmap", optional=True)
    add("geo", "IP geolocation database", (config.DATA / "geo.db").exists(), "", "runs on first `geo.py` timer", optional=True)

    if config.get("cloudflare.zone_id"):
        tok = config.get("cloudflare.token_secret") or "CF_API_TOKEN"
        add("cloudflare", "Cloudflare token", secrets.have(tok), f"secret {tok}",
            "create a token with Zone WAF:Edit + Analytics:Read", optional=True)
    if config.get("ids.suricata_host"):
        add("ids", "Network IDS source", True, config.get("ids.suricata_host"), optional=True)

    try:
        from . import tokens  # noqa: PLC0415
        live = [t for t in tokens.listing() if not t["revoked"]]
        add("api", "API / MCP token issued", bool(live), f"{len(live)} active",
            "Settings → Connect an agent → New token (or `warden-setup token <name>`)", optional=True)
    except sqlite3.Error:
        pass
    return out


def score(rows):
    req = [r for r in rows if not r["optional"]]
    return {"required_ok": sum(r["ok"] for r in req), "required": len(req),
            "optional_ok": sum(r["ok"] for r in rows if r["optional"]), "optional": sum(r["optional"] for r in rows)}
