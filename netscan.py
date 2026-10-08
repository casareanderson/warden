#!/usr/bin/env python3
"""netscan — the inside-the-network half of warden.

warden reads logs, which only ever show you traffic that reached an
application. netscan looks at the network itself: what is actually plugged
in, what it is listening on, and what changed since last time.

It answers the questions no log can:
  - is there a device on this LAN that has never been here before?
  - did a host that used to be quiet just start listening on a new port?
  - did a known device move to a different address?
  - is something else now answering on an address that belonged to a service?

That last one is not hypothetical here. A smart bulb once took the password
manager's lease, and the proxy container losing its own lease was read as
"the SSO portal is down" 87 times. Both are IP-identity failures, and both are invisible in every log
the estate collects.

⚠️ DETECT-ONLY BY DESIGN. netscan never blocks, isolates or changes a device.
It records and it tells you. There is no enforcement path in this file at all,
deliberately: the blast radius of an automated action against a LAN device
(your own laptop, the printer, a door sensor) is far worse than a late alert.

⚠️ BASELINE, AND WHY ONE SWEEP IS NOT ENOUGH
The first sweep records every device it finds as already-approved and raises
no new-device alerts — otherwise turning it on means 40 alerts about things
that have been here for two years, and you learn to ignore it on day one.

But one sweep is not a baseline either. An ARP sweep only sees what is awake:
measured here, two consecutive sweeps twelve minutes apart found 48 then 46
devices, with six "new" ones that were simply asleep the first time (WiZ
bulbs, a Nest, the TV). Alerting on those is the same false-alarm problem
wearing a different hat. So there is a LEARNING WINDOW (`learn_hours`, default
48): anything first seen inside it is recorded and approved silently, and
NEW_DEVICE alerts only begin once the estate has had time to show its full
population across many sweeps.

Conflicts, critical-host absence and port changes are NOT suppressed during
learning — those are stateful comparisons that are meaningful immediately.
"""
import json
import os
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from wlib import config as wcfg  # noqa: E402

DB = Path(wcfg.DB)                        # shared store: one place to look
CONF = wcfg.HOME / "netscan.yml"
OUI_FILE = "/usr/share/nmap/nmap-mac-prefixes"   # ships with nmap, no download

# --------------------------------------------------------------- config ---
DEFAULTS = {
    "networks": ["192.168.1.0/24"],
    "port_scan": True,
    "top_ports": 200,
    # Hosts whose disappearance is worth an alert. Everything else on a home
    # LAN comes and goes (phones, laptops, a printer that sleeps) and alerting
    # on that is pure noise.
    "critical": [],
    "alert": True,
    # Hours from the first ever sweep during which newly-seen devices are
    # adopted silently. See the module docstring: a home LAN reveals its real
    # population over days, not in one sweep.
    "learn_hours": 48,
}


def load_conf():
    """Same deliberately tiny YAML subset warden uses — no PyYAML on this box."""
    cfg = dict(DEFAULTS)
    if wcfg.get("estate.lan"):            # warden.yml's LAN list is the default sweep
        cfg["networks"] = list(wcfg.get("estate.lan"))
    if not CONF.exists():
        return cfg
    key = None
    for raw in CONF.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and key:
            cfg.setdefault(key, []).append(line[4:].strip().strip('"\''))
            continue
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip().strip('"\'')
            key = k
            if v == "":
                cfg[k] = []
            elif v.lower() in ("true", "false"):
                cfg[k] = v.lower() == "true"
            elif v.isdigit():
                cfg[k] = int(v)
            else:
                cfg[k] = v
    return cfg


# ------------------------------------------------------------------ db ----
SCHEMA = """
create table if not exists net_hosts(
  mac text primary key, ip text, hostname text, vendor text,
  first_seen text, last_seen text, approved integer default 0, note text);
create table if not exists net_ports(
  mac text, port integer, proto text, service text,
  first_seen text, last_seen text, primary key(mac, port, proto));
create table if not exists net_alerts(
  id integer primary key, ts text, kind text, mac text, ip text,
  detail text, notified integer default 0);
create table if not exists net_host_ips(
  mac text, ip text, first_seen text, last_seen text, primary key(mac, ip));
create table if not exists net_runs(
  id integer primary key, ts text, network text, hosts integer, note text);
create index if not exists nh_ip on net_hosts(ip);
create index if not exists na_ts on net_alerts(ts);
"""


def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


# ------------------------------------------------------------------ oui ---
_oui = None

# nmap's shipped prefix table is a snapshot (the packaged one here is dated
# April 2024) and does not know newer allocations. Anything genuinely certain
# and relevant to this estate goes here and wins over the file.
#
# Only entries that are verifiable go in this map. A guessed vendor name is
# worse than a blank one: it makes an unknown device look identified.
OUI_EXTRA = {
    "BC2411": "Proxmox VE (virtual NIC)",   # every LXC/VM on both nodes
}


def is_random_mac(mac):
    """True if the MAC has the locally-administered bit set.

    Modern phones and laptops rotate a random per-network MAC by default, so
    these appear as brand-new devices whenever the address rolls. Knowing that
    an address is randomised is the difference between "unknown intruder" and
    "somebody's phone did its normal thing".
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0b10)
    except (ValueError, IndexError):
        return False


def vendor_of(mac):
    """Resolve a MAC to a vendor using nmap's own prefix table.

    ⚠️ Do NOT identify a device by its hostname. The BG/Broadlink plugs in this
    estate announce themselves as "Luceco" and were only ever found by OUI
    (a0:43:b0). Hostnames are chosen by the device; the OUI is assigned to the
    manufacturer, so it is the far stronger signal.
    """
    global _oui
    if _oui is None:
        _oui = {}
        try:
            for line in open(OUI_FILE, encoding="utf-8", errors="replace"):
                if line.startswith("#") or " " not in line:
                    continue
                pre, name = line.rstrip("\n").split(" ", 1)
                _oui[pre.upper()] = name.strip()
        except OSError:
            pass
    if not mac:
        return ""
    pre = mac.replace(":", "").upper()[:6]
    if pre in OUI_EXTRA:
        return OUI_EXTRA[pre]
    hit = _oui.get(pre, "")
    if hit:
        return hit
    if is_random_mac(mac):
        return "randomised MAC (private Wi-Fi address)"
    # Say WHY it is blank. An empty vendor column reads as "suspicious unknown
    # device"; in practice every blank here was a known device (the EAP610 AP,
    # an August lock, eufy, the TL-SG108E switch, an Apple TV) whose OUI simply
    # postdates nmap's packaged table. Naming the cause stops a stale lookup
    # table from looking like an intrusion.
    return f"unknown (OUI {pre[:2]}:{pre[2:4]}:{pre[4:6]} not in table)"


# ----------------------------------------------------------------- scan ---
def run_nmap(args, timeout=900):
    """Run nmap and return parsed XML, or None. Never raises into the caller."""
    try:
        p = subprocess.run(["nmap", "-oX", "-"] + args,
                           capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"netscan: nmap failed: {e}", file=sys.stderr)
        return None
    if not p.stdout.strip():
        print(f"netscan: nmap produced nothing: {p.stderr[:200]}", file=sys.stderr)
        return None
    try:
        return ET.fromstring(p.stdout)
    except ET.ParseError as e:
        print(f"netscan: bad nmap xml: {e}", file=sys.stderr)
        return None


def discover(network):
    """ARP ping sweep. -PR is L2, so it finds devices that drop ICMP —
    a firewalled host or a privacy-mode phone still has to answer ARP to use
    the network at all. -n keeps DNS out of it; a slow resolver must not be
    able to stall a sweep."""
    root = run_nmap(["-sn", "-PR", "-n", "--max-retries", "1", network], timeout=600)
    hosts = []
    if root is None:
        return hosts
    for h in root.findall("host"):
        if (h.find("status") is not None
                and h.find("status").get("state") != "up"):
            continue
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                mac = (a.get("addr") or "").lower()
                vendor = a.get("vendor", "") or ""
        if not ip:
            continue
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor or vendor_of(mac)})
    return hosts


def scan_ports(ips, top_ports):
    """TCP connect scan of the discovered hosts.

    -sT (connect) not -sS (SYN): this runs in an unprivileged LXC where raw
    sockets are not reliably available, and a SYN scan that silently falls back
    produces confusing results. Connect scan is slower but it is honest.
    """
    if not ips:
        return {}
    root = run_nmap(["-sT", "-n", "-Pn", "--top-ports", str(top_ports),
                     "--open", "--max-retries", "1", "--host-timeout", "60s"]
                    + list(ips), timeout=1800)
    out = {}
    if root is None:
        return out
    for h in root.findall("host"):
        ip = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
        if not ip:
            continue
        ports = []
        pel = h.find("ports")
        if pel is None:
            continue
        for p in pel.findall("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol", "tcp"),
                "service": (svc.get("name") if svc is not None else "") or "",
            })
        out[ip] = ports
    return out


def resolve_name(ip):
    """Best-effort reverse name. Purely cosmetic — an alert must still be
    readable when DNS says nothing, so failure here is not an error."""
    try:
        p = subprocess.run(["getent", "hosts", ip],
                           capture_output=True, text=True, timeout=5)
        if p.returncode == 0 and p.stdout.split():
            return p.stdout.split()[-1]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------- alerts --
def raise_alert(con, ts, kind, mac, ip, detail):
    con.execute("insert into net_alerts(ts,kind,mac,ip,detail) values(?,?,?,?,?)",
                (ts, kind, mac, ip, detail))


def main():
    cfg = load_conf()
    # Discovery is an ARP sweep and takes seconds; the port scan is a TCP
    # connect scan of every host and takes minutes. They run on different
    # timers, so the fast path needs a way to skip the slow half.
    if "--no-ports" in sys.argv:
        cfg["port_scan"] = False
    con = db()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Is this the very first sweep? If so everything found becomes the
    # baseline and nothing alerts. See the module docstring.
    baseline = con.execute("select count(*) c from net_hosts").fetchone()["c"] == 0

    # Still inside the learning window? Compare against the FIRST run ever
    # recorded, not against wall-clock uptime, so restarting the service or
    # the container does not silently restart learning.
    first_run = con.execute("select min(ts) t from net_runs").fetchone()["t"]
    learning = baseline
    if not baseline and first_run:
        learning = con.execute(
            "select (julianday('now') - julianday(?)) * 24 < ? as l",
            (first_run, cfg["learn_hours"])).fetchone()["l"] == 1

    if baseline:
        print("netscan: no prior data — this run establishes the baseline, "
              "no new-device alerts will be raised")
    elif learning:
        print(f"netscan: LEARNING (first run {first_run}, window "
              f"{cfg['learn_hours']}h) — new devices adopted silently")

    found = []
    for net in cfg["networks"]:
        hs = discover(net)
        con.execute("insert into net_runs(ts,network,hosts,note) values(?,?,?,?)",
                    (now, net, len(hs),
                     "baseline" if baseline else ("learning" if learning else "")))
        found.extend(hs)

    # A sweep that finds nothing is almost always a broken sweep (no nmap, no
    # interface, no permission), not an empty network. Treat it as an error and
    # change no state — otherwise every known host looks like it vanished.
    if not found:
        con.commit()
        print("netscan: ERROR — sweep returned 0 hosts, leaving state untouched",
              file=sys.stderr)
        con.close()
        return 1

    # A MAC answering at several addresses WITHIN ONE SWEEP has not "moved" —
    # every address is live at the same instant, so the device is multi-homed.
    # This has to be decided BEFORE the per-host loop, because deciding it
    # inside the loop reports the same device twice: the first address looks
    # like a move away from the stored one, and the second looks like the
    # conflict. A Sonos speaker holding .114 and .177 produced exactly that
    # pair of alerts. One device, one finding.
    ips_by_mac = {}
    for h in found:
        if h["mac"]:
            ips_by_mac.setdefault(h["mac"], []).append(h["ip"])
    multi_homed = {m: sorted(set(v)) for m, v in ips_by_mac.items() if len(set(v)) > 1}
    for mac, ips in multi_homed.items():
        vend = next((h["vendor"] for h in found if h["mac"] == mac), "")
        raise_alert(con, now, "MAC_MULTI_IP", mac, ips[0],
                    f"{vend or 'device'} answering on {len(ips)} addresses in "
                    f"one sweep: {', '.join(ips)}")

    seen_macs = set()
    for h in found:
        ip, mac, vendor = h["ip"], h["mac"], h["vendor"]
        # A host with no MAC is one the scanner could not see at L2 — usually
        # the scanner's own address, or something routed. Skip: a blank MAC is
        # not an identity and would collide in the primary key.
        if not mac:
            continue
        if mac in seen_macs:
            continue
        seen_macs.add(mac)
        name = resolve_name(ip)
        con.execute("insert into net_host_ips(mac,ip,first_seen,last_seen) "
                    "values(?,?,?,?) on conflict(mac,ip) do update set "
                    "last_seen=excluded.last_seen", (mac, ip, now, now))
        prior = con.execute("select * from net_hosts where mac=?", (mac,)).fetchone()

        if prior is None:
            con.execute(
                "insert into net_hosts(mac,ip,hostname,vendor,first_seen,"
                "last_seen,approved) values(?,?,?,?,?,?,?)",
                (mac, ip, name, vendor, now, now, 1 if learning else 0))
            if not learning:
                raise_alert(con, now, "NEW_DEVICE", mac, ip,
                            f"unknown device joined: {vendor or 'unknown vendor'}"
                            f"{' / ' + name if name else ''}")
        else:
            # Known MAC on a new address. Worth knowing: it is how DHCP churn
            # shows up, and churn here has twice been misdiagnosed as an outage.
            # Multi-homed devices are excluded — already reported once above,
            # and their "current" address flaps between sweeps by definition.
            # Alert only the FIRST time this MAC is seen at this address.
            #
            # ⚠️ Without this, a device that flaps between two leases alerts on
            # every single sweep, forever. The Sonos here alternates .114/.177
            # and would have produced an IP_CHANGE every 15 minutes — a rule
            # that fires constantly is one you mute, which costs you the real
            # DHCP-churn detection this check exists for. History keeps the
            # first move visible and the flapping quiet.
            known_here = con.execute(
                "select 1 from net_host_ips where mac=? and ip=?",
                (mac, ip)).fetchone()
            if prior["ip"] != ip and mac not in multi_homed and not known_here:
                raise_alert(con, now, "IP_CHANGE", mac, ip,
                            f"{vendor or 'device'} moved {prior['ip']} -> {ip}")
            con.execute("update net_hosts set ip=?, hostname=?, vendor=?, "
                        "last_seen=? where mac=?",
                        (ip, name or prior["hostname"], vendor or prior["vendor"],
                         now, mac))

    # Two different MACs answering on one address inside a single sweep. This
    # is the smart-bulb-steals-the-password-manager's-lease case (measured, not hypothetical), and it is the reason this
    # check exists rather than being a theoretical nicety.
    by_ip = {}
    for h in found:
        if h["mac"]:
            by_ip.setdefault(h["ip"], set()).add(h["mac"])
    for ip, macs in by_ip.items():
        if len(macs) > 1:
            raise_alert(con, now, "IP_CONFLICT", ",".join(sorted(macs)), ip,
                        f"{len(macs)} MACs answering on {ip} — lease collision "
                        f"or spoofing")

    # --- ports ----------------------------------------------------------
    if cfg["port_scan"]:
        ip_by_mac = {h["mac"]: h["ip"] for h in found if h["mac"]}
        portmap = scan_ports(sorted(set(ip_by_mac.values())), cfg["top_ports"])
        for mac, ip in ip_by_mac.items():
            for p in portmap.get(ip, []):
                row = con.execute(
                    "select first_seen from net_ports where mac=? and port=? "
                    "and proto=?", (mac, p["port"], p["proto"])).fetchone()
                if row is None:
                    con.execute(
                        "insert into net_ports(mac,port,proto,service,"
                        "first_seen,last_seen) values(?,?,?,?,?,?)",
                        (mac, p["port"], p["proto"], p["service"], now, now))
                    # A newly-listening port on a device that was already here
                    # is the interesting signal: it means something started
                    # serving that was not serving before.
                    if not learning and mac in {h["mac"] for h in found}:
                        known = con.execute(
                            "select approved, vendor from net_hosts where mac=?",
                            (mac,)).fetchone()
                        if known and known["approved"]:
                            raise_alert(
                                con, now, "NEW_PORT", mac, ip,
                                f"{ip} ({known['vendor'] or 'device'}) now "
                                f"listening on {p['port']}/{p['proto']}"
                                f"{' ' + p['service'] if p['service'] else ''}")
                else:
                    con.execute("update net_ports set last_seen=?, service=? "
                                "where mac=? and port=? and proto=?",
                                (now, p["service"], mac, p["port"], p["proto"]))

    # --- critical hosts missing -----------------------------------------
    for ident in cfg.get("critical", []):
        hit = con.execute(
            "select mac, ip, last_seen from net_hosts where ip=? or mac=?",
            (ident, ident.lower())).fetchone()
        if hit and hit["last_seen"] != now:
            raise_alert(con, now, "CRITICAL_MISSING", hit["mac"], hit["ip"],
                        f"critical host {ident} did not answer this sweep "
                        f"(last seen {hit['last_seen']})")

    con.commit()
    n_alerts = con.execute(
        "select count(*) c from net_alerts where ts=? ", (now,)).fetchone()["c"]
    print(f"netscan: {len(seen_macs)} devices, {n_alerts} alert(s)"
          f"{' [baseline]' if baseline else (' [learning]' if learning else '')}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
