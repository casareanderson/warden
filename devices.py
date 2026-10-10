#!/usr/bin/env python3
"""devices.py — one inventory of every networked thing in the house, and what KIND of thing each one is.

Owner 2026-10-10: "warden is picking up stuff like IoT and everything in the house … smart decisions on detection".
This is step 1 of 3: know every device. (2: learn each device's normal behaviour; 3: score and decide.)

Sources, merged on the MAC address (all read-only, all optional):
  netscan   net_hosts: what answered an ARP sweep, with the NIC vendor (warden's own LAN sweep)
  router    DHCP leases over the same read-only SSH netintel uses (`router.ssh`): every client the router
            handed an address to, on EVERY network/VLAN, with the name the device asked for
  ha        Home Assistant's device + area registry over its WebSocket API (`ha.url` + secret named in
            `ha.token_secret`, a long-lived token the OWNER creates in HA → Profile → Security): friendly
            names, rooms, manufacturer and model, and which entity types (light, media_player…) it exposes

Kind is decided by rules, strongest evidence first: HA entity types > HA manufacturer/model > hostname >
NIC vendor. Every device records WHY it got its kind (`kind_why`) so a wrong guess can be traced. No LLM.
"Fixed-function" kinds (bulb, plug, speaker, tv, camera, printer, iot, hub, network) are the ones whose
normal behaviour is narrow; step 2 learns that and step 3 treats a change in it as meaningful.

  devices.py            refresh the inventory (timer: every 15 min, after netscan)
  devices.py --show     print it
"""
import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wlib import config, secrets  # noqa: E402

FIXED = {"bulb", "light", "plug", "speaker", "tv", "camera", "printer", "iot", "hub", "network"}
# "personal" = a phone/laptop/tablet using a private (randomised) Wi-Fi address: it changes address, so warden
# groups those by the name the device gives the router (one laptop showed up as 27 addresses on 2026-10-10)

# (pattern, kind) — matched case-insensitively against the text named in each rule set
HA_DOMAIN_KIND = [("camera", "camera"), ("vacuum", "iot"), ("climate", "iot"), ("lock", "iot"), ("light", "bulb"),
                  ("media_player", "speaker"), ("switch", "plug")]
MODEL_KIND = [(r"\b(tv|bravia|qled|oled|webos|tizen|fire ?tv|roku|chromecast|google tv)\b", "tv"),
              (r"\b(sonos|echo|nest (mini|audio|hub)|homepod|google home|speaker)\b", "speaker"),
              (r"\b(plug|socket|sp\d|outlet)\b", "plug"), (r"\b(bulb|lamp|light|led|wled|strip)\b", "bulb"),
              (r"\b(camera|cam|doorbell|eufy)\b", "camera"), (r"\b(printer|laserjet|officejet|deskjet|envy)\b", "printer"),
              (r"\b(hub|bridge|zigbee|coordinator)\b", "hub")]
HOST_KIND = [(r"appletv|apple-tv|webos|lgwebos|bravia|roku|firetv|chromecast|androidtv|\btv\b|-tv\b", "tv"),
             (r"eero|tl-sg|tl-|unifi|eap\d|deco|orbi|router|mesh|switch\d|streamlocator", "network"),
             (r"augustconnect|august|bt-proxy|esphome|tasmota|shelly|lwip|^esp|esp32|esp8266", "iot"),
             (r"^s380|homebase|^t8\d{3}", "camera"),
             (r"klipper|voron|octoprint|mainsail|fluidd", "printer"),
             (r"^bl-|broadlink", "plug"),
             (r"iphone|ipad|galaxy|pixel|android|oneplus|redmi|huawei|phone", "phone"),
             (r"macbook|laptop|desktop|-pc\b|^pc-|windows|imac|thinkpad|surface", "computer"),
             (r"wled|wiz|bulb|light|lamp", "bulb"), (r"sonos|echo|nest|homepod|speaker", "speaker"),
             (r"printer|^hp|epson|brother|canon", "printer"), (r"cam|doorbell|eufy", "camera"),
             (r"^esp|esp32|esp8266|tasmota|shelly", "iot"), (r"xbox|playstation|ps5|ps4|switch-|nintendo", "console"),
             (r"proxmox|pve|server|nas|zima|raspberrypi|^pi\b", "server"), (r"router|ap-|eap\d|switch\b|mesh", "network")]
VENDOR_KIND = [(r"wiz", "bulb"), (r"broadlink", "plug"), (r"sonos", "speaker"), (r"espressif", "iot"),
               (r"intellirocks|govee", "bulb"), (r"amazon", "speaker"), (r"google", "speaker"),
               (r"raspberry pi", "server"), (r"proxmox", "server"), (r"hewlett packard|epson|brother|canon", "printer"),
               (r"tp-?link|ubiquiti|netgear|gl technologies|gl\.inet|mikrotik", "network"),
               (r"apple", "phone"), (r"randomised mac|private wi-?fi", "personal"),
               (r"samsung|lg electronics|sony|vestel", "tv"), (r"gaoshengda|feitengyun|tuya|realtek.*wlan", "iot"),
               (r"intel|dell|lenovo|asustek|micro-star|gigabyte", "computer")]


def db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists devices(mac text primary key, ip text, name text, room text, kind text, kind_why text,
        fixed integer, maker text, model text, sources text, ha_id text, first_seen text, last_seen text, updated text,
        identity text);
      create index if not exists dev_ip on devices(ip);""")
    if "identity" not in [r[1] for r in con.execute("pragma table_info(devices)")]:
        con.execute("alter table devices add column identity text")
    return con


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def norm_mac(m):
    m = (m or "").lower().replace("-", ":")
    return m if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", m) else ""


def from_netscan(con):
    try:
        rows = con.execute("select mac, ip, hostname, vendor, first_seen, last_seen from net_hosts").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {norm_mac(r["mac"]): dict(r) for r in rows if norm_mac(r["mac"])}


def from_router():
    """OpenWrt-style /tmp/dhcp.leases: '<expiry> <mac> <ip> <hostname|*> <clientid>'. Empty if no router."""
    if not config.get("router.ssh"):
        return {}, "no router configured"
    key = config.get("router.key")
    cmd = (["ssh"] + (["-i", key] if key else []) + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           config.get("router.ssh"), "cat " + (config.get("router.leases") or "/tmp/dhcp.leases")])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {}, "router timed out"
    if p.returncode != 0:
        return {}, f"router: {(p.stderr or '').strip()[:120]}"
    out = {}
    for ln in p.stdout.splitlines():
        f = ln.split()
        if len(f) >= 4 and norm_mac(f[1]):
            out[norm_mac(f[1])] = {"ip": f[2], "hostname": "" if f[3] == "*" else f[3]}
    return out, f"{len(out)} leases"


def from_ha():
    """Home Assistant device/area/entity registries over WebSocket. Empty (with the reason) if not configured."""
    url, sec = config.get("ha.url"), config.get("ha.token_secret") or "HA_TOKEN"
    tok = secrets.get(sec) if url else None
    if not url:
        return {}, "no ha.url"
    if not tok:
        return {}, f"no token (secret {sec}): create one in HA → Profile → Security → Long-lived access tokens"
    try:
        import websocket
    except ImportError:
        return {}, "python websocket-client not installed"
    ws_url = re.sub(r"^http", "ws", url.rstrip("/")) + "/api/websocket"
    try:
        ws = websocket.create_connection(ws_url, timeout=20)
        ws.recv(); ws.send(json.dumps({"type": "auth", "access_token": tok}))
        if json.loads(ws.recv()).get("type") != "auth_ok":
            return {}, "HA rejected the token"
        res = {}
        for i, t in enumerate(("config/device_registry/list", "config/area_registry/list", "config/entity_registry/list"), 1):
            ws.send(json.dumps({"id": i, "type": t}))
            while True:
                m = json.loads(ws.recv())
                if m.get("id") == i:
                    res[t] = m.get("result") or []; break
        ws.close()
    except Exception as e:  # noqa: BLE001
        return {}, f"HA: {type(e).__name__}: {str(e)[:100]}"
    areas = {a["area_id"]: a["name"] for a in res["config/area_registry/list"]}
    doms = {}
    for e in res["config/entity_registry/list"]:
        if e.get("device_id") and not e.get("disabled_by"):
            doms.setdefault(e["device_id"], set()).add(e["entity_id"].split(".")[0])
    out = {}
    for d in res["config/device_registry/list"]:
        for kind, val in d.get("connections") or []:
            if kind == "mac" and norm_mac(val):
                out[norm_mac(val)] = {"ha_id": d["id"], "name": d.get("name_by_user") or d.get("name") or "",
                                      "room": areas.get(d.get("area_id"), ""), "maker": d.get("manufacturer") or "",
                                      "model": d.get("model") or "", "domains": sorted(doms.get(d["id"], []))}
    return out, f"{len(out)} devices with a MAC (of {len(res['config/device_registry/list'])} in HA)"


def declared_ips():
    """Machines warden.yml already declares (hosts: ssh user@ip) are servers by definition."""
    out = set()
    for h in config.get("hosts") or []:
        m = re.search(r"@?(\d+\.\d+\.\d+\.\d+)", str((h or {}).get("ssh", "")))
        if m:
            out.add(m.group(1))
    return out


def identity(mac, hostname, vendor):
    """Private-address devices are grouped by the name they give; everything else is its MAC."""
    rnd = mac and mac[1] in "26ae"
    generic = re.fullmatch(r"(i?phone|ipad|mac|macbook(-pro|-air)?|android(-[0-9a-f]+)?|galaxy.*|pixel.*|localhost|"
                           r"wlan0|unknown|\*)(\.lan|\.local)?", (hostname or "").lower())
    if (rnd or "randomised" in (vendor or "").lower()) and hostname and not generic:   # two people's "iPhone" ≠ one device
        return "host:" + re.sub(r"\.lan$|\.local$", "", hostname.lower())
    return "mac:" + mac


def classify(ha, hostname, vendor, ip="", servers=frozenset()):
    """(kind, why). Strongest evidence first."""
    if ip and ip in servers:
        return "server", "declared in warden.yml hosts"
    for dom, kind in HA_DOMAIN_KIND:
        if dom in (ha.get("domains") or []):
            mk = f"{ha.get('maker', '')} {ha.get('model', '')}"
            if dom == "media_player":                       # a speaker or a TV: the model says which
                for pat, k in MODEL_KIND:
                    if k in ("tv", "speaker") and re.search(pat, mk, re.I):
                        return k, f"HA media_player, model '{mk.strip()}'"
            if dom == "switch" and not re.search(r"\b(plug|socket|outlet|sp\d+)\b", mk + " " + ha.get("name", ""), re.I):  # not "eSP32"
                continue                                    # many things expose a switch; only plugs ARE one
            return kind, f"HA exposes {dom}"
    mk = f"{ha.get('maker', '')} {ha.get('model', '')}".strip()
    for pat, kind in MODEL_KIND:
        if mk and re.search(pat, mk, re.I):
            return kind, f"HA model '{mk}'"
    for pat, kind in HOST_KIND:
        if hostname and re.search(pat, hostname, re.I):
            return kind, f"hostname '{hostname}'"
    for pat, kind in VENDOR_KIND:
        if vendor and re.search(pat, vendor, re.I):
            return kind, f"NIC vendor '{vendor}'"
    return "unknown", "no rule matched"


def refresh():
    con = db()
    ns = from_netscan(con)
    rt, rt_note = from_router()
    ha, ha_note = from_ha()
    ts = now()
    servers = declared_ips()
    macs = set(ns) | set(rt) | set(ha)
    for mac in macs:
        n, r, h = ns.get(mac, {}), rt.get(mac, {}), ha.get(mac, {})
        hostname = r.get("hostname") or n.get("hostname") or ""
        vendor = n.get("vendor") or ""
        ip = r.get("ip") or n.get("ip") or ""
        kind, why = classify(h, hostname, vendor, ip, servers)
        if kind == "unknown" and mac[1] in "26ae":
            kind, why = "personal", "private (randomised) Wi-Fi address"
        name = h.get("name") or hostname or vendor or mac
        src = ",".join(s for s, d in (("netscan", n), ("router", r), ("ha", h)) if d)
        prev = con.execute("select first_seen from devices where mac=?", (mac,)).fetchone()
        first = (prev["first_seen"] if prev else None) or n.get("first_seen") or ts
        last = ts if r else (n.get("last_seen") or ts)          # a live DHCP lease = here now
        con.execute("""insert into devices(mac, ip, name, room, kind, kind_why, fixed, maker, model, sources, ha_id,
                         first_seen, last_seen, updated, identity) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       on conflict(mac) do update set ip=excluded.ip, name=excluded.name, room=excluded.room,
                         kind=excluded.kind, kind_why=excluded.kind_why, fixed=excluded.fixed, maker=excluded.maker,
                         model=excluded.model, sources=excluded.sources, ha_id=excluded.ha_id,
                         last_seen=excluded.last_seen, updated=excluded.updated, identity=excluded.identity""",
                    (mac, ip, name[:80], h.get("room", ""), kind, why,
                     1 if kind in FIXED else 0, h.get("maker") or vendor, h.get("model", ""), src, h.get("ha_id", ""),
                     first, last, ts, identity(mac, hostname, vendor)))
    if con.execute("select name from sqlite_master where name='runs'").fetchone():   # shows on the Health tab
        con.execute("insert into runs(ts, source, lines, parsed, note) values(?,?,?,?,?)",
                    (ts, "devices", len(macs), len(ha), f"netscan {len(ns)} · router {rt_note} · HA {ha_note}"))
    con.commit()
    kinds = {}
    for r in con.execute("select kind, count(distinct identity) n from devices group by kind"):
        kinds[r["kind"]] = r["n"]
    ids = con.execute("select count(distinct identity) from devices").fetchone()[0]
    print(f"devices: {ids} real devices from {len(macs)} addresses (netscan {len(ns)} · router {rt_note} · HA {ha_note}) · "
          + " ".join(f"{k}={v}" for k, v in sorted(kinds.items(), key=lambda x: -x[1])))


def show():
    con = db()
    for r in con.execute("select * from devices order by kind, name"):
        print(f"{r['kind']:<9} {r['ip']:<15} {r['name'][:28]:<28} {r['room'][:14]:<14} {r['sources']:<18} {r['kind_why']}")


if __name__ == "__main__":
    show() if "--show" in sys.argv else refresh()
