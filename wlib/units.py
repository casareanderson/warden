"""systemd units, generated for wherever warden is installed.

Each unit belongs to a feature group. `warden-setup units --install` enables a
group only when warden.yml says that feature is in use, so a box with no
Cloudflare zone never runs the Cloudflare jobs and fails noisily every hour.
"""
import sys
from pathlib import Path

from . import config, hosts

# name: (group, description, args, schedule, extra service lines)
# schedule: ("every", "5min", boot) | ("calendar", "*-*-* 03:30") | None (long-running)
UNITS = {
    "warden":                 ("core", "warden — score log events, propose bans (detect-only by default)",
                               ["warden.py"], ("every", "5min", "3min"), []),
    "warden-ui":              ("core", "warden console, REST API and MCP connector", ["warden-ui.py"], None, []),
    "warden-siemalert":       ("core", "warden — push new findings to your alerts channel",
                               ["siemalert.py"], ("every", "5min", "8min"), []),
    "warden-geo":             ("core", "warden — refresh the DB-IP country database (monthly)",
                               ["geo.py", "update"], ("calendar", "*-*-03 05:10"), []),
    "warden-netscan":         ("lan", "warden — LAN device discovery sweep (detect-only)",
                               ["netscan.py", "--no-ports"], ("every", "15min", "5min"), ["TimeoutStartSec=600"]),
    "warden-netscan-ports":   ("lan", "warden — TCP port sweep of known hosts (detect-only)",
                               ["netscan.py"], ("calendar", "*-*-* 04:20"), ["TimeoutStartSec=3600"]),
    "warden-vulnscan":        ("vuln", "warden — vulnerability scan of every box, image and firmware",
                               ["vulnscan.py"], ("calendar", "*-*-* 03:30"),
                               ["TimeoutStartSec=5400", "ExecStartPost=@PYTHON@ @HOME@/images.py"]),
    "warden-patcher":         ("patch", "warden — patch requests → plan → owner approval → snapshot + upgrade",
                               ["patcher.py", "run"], ("every", "2min", "3min"), ["TimeoutStartSec=7200"]),
    "warden-patch-auto":      ("patch", "warden — daily patch round (queues REQUESTS; each plan still needs approval)",
                               ["patcher.py", "auto"], ("calendar", "*-*-* 06:20"), []),
    "warden-integrity-poll":  ("integrity", "warden integrity — apply owner decisions",
                               ["integrity.py", "poll"], ("every", "10min", "7min"), ["TimeoutStartSec=3600"]),
    "warden-integrity-sweep": ("integrity", "warden integrity — agentless endpoint drift",
                               ["integrity.py"], ("calendar", "*-*-* *:40"), ["TimeoutStartSec=3600"]),
    "warden-integrity-deep":  ("integrity", "warden integrity — deep sweep",
                               ["integrity.py", "--deep"], ("calendar", "*-*-* 04:10"), ["TimeoutStartSec=3600"]),
    "warden-harden":          ("integrity", "warden — weekly hardening audit (temporary Lynis, nothing left installed)",
                               ["harden.py"], ("calendar", "Sun *-*-* 05:00"), ["TimeoutStartSec=7200"]),
    "warden-intel":           ("cloudflare", "warden intel — Cloudflare edge events + external attack surface",
                               ["intel.py", "all"], ("calendar", "hourly"), ["TimeoutStartSec=900"]),
    "warden-geo-apply":       ("cloudflare", "warden — apply the console's country-block switch at the Cloudflare edge",
                               ["cfsec.py", "--apply-geo", "--commit", "--if-pending"], ("every", "1min", "2min"), []),
    "warden-edgeban-propose": ("cloudflare", "warden edge blocklist — hourly proposals",
                               ["edgeban.py", "propose"], ("calendar", "*-*-* *:20"), []),
    "warden-edgeban-poll":    ("cloudflare", "warden edge blocklist — apply owner decisions",
                               ["edgeban.py", "poll"], ("every", "10min", "6min"), []),
    "warden-netids":          ("ids", "warden — pull network IDS (Suricata) alerts",
                               ["netids.py"], ("every", "5min", "4min"), []),
    "warden-netintel":        ("router", "warden — router DNS log + conntrack vs threat feeds",
                               ["netintel.py"], ("every", "10min", "5min"), []),
    "warden-devices":         ("lan", "warden — one inventory of every device (sweep + router leases + Home Assistant)",
                               ["devices.py"], ("every", "15min", "6min"), []),
    "warden-netwatch":        ("router", "warden — internet health every minute (router, internet, DNS, web, line usage)",
                               ["netwatch.py"], ("every", "1min", "2min"), ["TimeoutStartSec=55"]),
    "warden-devicewatch":     ("router", "warden — score fixed-function devices doing something new; ask the owner on odd ones",
                               ["devicewatch.py"], ("every", "10min", "9min"), ["TimeoutStartSec=1200"]),
}

GROUPS = {
    "core": "always",
    "lan": "nmap installed",
    "vuln": "trivy installed and at least one host declared",
    "patch": "a host with `patch: true`",
    "integrity": "at least one host declared",
    "cloudflare": "cloudflare.zone_id set",
    "ids": "ids.suricata_host set",
    "router": "router.ssh set",
}


def enabled_groups():
    import os
    import shutil
    have_hosts = bool(hosts.declared())
    return {
        "core": True,
        "lan": bool(shutil.which("nmap")),
        "vuln": have_hosts and os.path.exists(config.get("vuln.trivy") or ""),
        "patch": any(h.get("patch") for h in hosts.declared()),
        "integrity": have_hosts,
        "cloudflare": bool(config.get("cloudflare.zone_id")),
        "ids": bool(config.get("ids.suricata_host")),
        "router": bool(config.get("router.ssh")),
    }


def render(name, python=None):
    group, desc, args, sched, extra = UNITS[name]
    home, data, py = str(config.HOME), str(config.DATA), python or sys.executable
    log = f"/var/log/{name}.log"
    sub = lambda s: s.replace("@HOME@", home).replace("@PYTHON@", py)  # noqa: E731
    svc = ["[Unit]", f"Description={desc}", "After=network-online.target", "Wants=network-online.target", "",
           "[Service]", f"WorkingDirectory={home}", f"Environment=WARDEN_HOME={home}", f"Environment=WARDEN_DATA={data}",
           f"ExecStart={py} " + " ".join(f"{home}/{a}" if a.endswith(".py") else a for a in args)]
    if sched is None:            # the web server: sandboxed, may write only its data directory
        svc += ["Restart=on-failure", "RestartSec=5", "ProtectSystem=strict", f"ReadOnlyPaths={home}",
                f"ReadWritePaths={data}", "PrivateTmp=true", "NoNewPrivileges=true"]
    else:
        svc += ["Type=oneshot", f"StandardOutput=append:{log}", f"StandardError=append:{log}"]
    svc += [sub(x) for x in extra]
    svc += ["", "[Install]", "WantedBy=multi-user.target"] if sched is None else []
    out = {f"{name}.service": "\n".join(svc) + "\n"}
    if sched:
        t = ["[Unit]", f"Description={desc} (timer)", "", "[Timer]"]
        if sched[0] == "every":
            t += [f"OnBootSec={sched[2]}", f"OnUnitActiveSec={sched[1]}", "RandomizedDelaySec=30"]
        else:
            t += [f"OnCalendar={sched[1]}", "Persistent=true"]
        t += ["", "[Install]", "WantedBy=timers.target"]
        out[f"{name}.timer"] = "\n".join(t) + "\n"
    return out


def plan():
    on = enabled_groups()
    return [(n, UNITS[n][0], on[UNITS[n][0]]) for n in UNITS]


def install(dest="/etc/systemd/system", python=None, dry=False):
    """Write every unit; return the list to enable (only the groups in use)."""
    enable = []
    for name, group, on in plan():
        for fn, text in render(name, python).items():
            if not dry:
                Path(dest, fn).write_text(text)
        if on:
            enable.append(f"{name}.timer" if UNITS[name][3] else f"{name}.service")
    return enable
