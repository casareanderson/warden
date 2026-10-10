#!/usr/bin/env python3
"""vulnscan.py — estate-wide vulnerability inventory for warden (built 2026-10-07). No LLM.

  vulnscan.py              scan everything (timer: daily 03:30), alert on new KEV / new fixable CRITICAL
  vulnscan.py <target>     scan one target (e.g. ct:101, node:10.0.0.2, img:nas) — used after a patch
  vulnscan.py --list       show targets + last results

HOW (nothing is installed on the scanned boxes, and there is no scanner binary at all):
  Debian/Ubuntu/Alpine boxes — copy ONLY the package DB + OS-identity files (dpkg status, os-release,
  apk db), parse them here and ask OSV.dev which advisories affect those exact versions (wlib/osv.py).
  Docker images — a small Python collector (wlib/imgcollect.py) is fed to `python3 -` on the docker host.
  It reads each running container's root through /proc and sends back only package metadata: OS packages,
  Python and npm packages, and Go build info. Only images of RUNNING containers are scanned.
  Vendor-firmware hosts (`firmware:` on a host, e.g. zimaos) — no package DB; tracked as a firmware version
  vs the vendor's latest release.

Targets come from wlib.hosts (warden.yml `hosts:`), so a new box is a config edit.

Until 2026-10-10 this used trivy. Its v0.69.4 release and v0.69.5/6 images were malicious (CVE-2026-33634), and
it needed a 161 MB binary, a 1.4 GB DB and a LAN server. OSV.dev is fed directly by Debian, Ubuntu, Alpine,
GitHub, PyPA and the Go team (see wlib/osv.py).
Priority = CISA KEV (known exploited) > CRITICAL with fix > HIGH with fix. Raw counts are mostly
"affected, no fix yet" upstream noise (one box: 4,592 CVEs, 0 fixable) — the UI leads with fixable/KEV.
"""
import io
import json
import os
import sqlite3
import sys
import tarfile
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify, osv  # noqa: E402
from wlib.imgcollect import SOURCE as COLLECTOR  # noqa: E402

DB = config.DB
KEV_FILE = str(config.DATA / "kev.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SSH = hosts.SSH
PKG_FILES = ["var/lib/dpkg/status", "etc/os-release", "usr/lib/os-release", "lib/apk/db/installed",
             "etc/alpine-release"]
FACTS = ("n=$(apt list --upgradable 2>/dev/null | grep -c / ); r=0; [ -f /var/run/reboot-required ] && r=1; "
         "k=$(uname -r); nk=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -1); "
         "echo \"$n $r $k ${nk:--}\"")
KERNEL_PKG = __import__("re").compile(r"^linux-(libc-dev|headers|image|modules|tools|kbuild|source)")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(m):
    print(f"{now()} {m}", flush=True)


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.executescript("""
      create table if not exists vuln_targets(
        target text primary key, kind text, name text, node text, vmid integer, os text,
        last_scan text, status text, note text, pkgs integer, upgradable integer,
        reboot_required integer, kernel text, newest_kernel text, patchable integer,
        n_total integer, n_fixable integer, n_crit_fix integer, n_high_fix integer, n_kev integer);
      create table if not exists vulns(
        target text, vid text, pkg text, installed text, fixed text, severity text, title text,
        kev integer, status text, image text, primary key(target, vid, pkg, image));
      create index if not exists vu_vid on vulns(vid);
    """)
    have = {r[1] for r in con.execute("pragma table_info(vulns)")}
    for col in ("descr", "url"):                 # added 2026-10-09: the CVE drawer shows what the CVE actually is
        if col not in have:
            con.execute(f"alter table vulns add column {col} text")
    return con


def run(cmd, timeout=300, binary=False, inp=None):
    return hosts.run(cmd, timeout=timeout, binary=binary, inp=inp)


# ── inputs ───────────────────────────────────────────────────────────────────
def kev_set():
    try:
        if not os.path.exists(KEV_FILE) or time.time() - os.path.getmtime(KEV_FILE) > 20 * 3600:
            r = requests.get(KEV_URL, timeout=60, headers={"User-Agent": "warden-vulnscan/1"})
            r.raise_for_status()
            json.loads(r.text)
            open(KEV_FILE, "w").write(r.text)
        return {v["cveID"] for v in json.load(open(KEV_FILE))["vulnerabilities"]}
    except Exception as e:  # noqa: BLE001 — stale KEV beats no scan; say so
        log(f"KEV refresh failed ({e}); using cached copy if any")
        try:
            return {v["cveID"] for v in json.load(open(KEV_FILE))["vulnerabilities"]}
        except Exception:  # noqa: BLE001
            return set()


def targets():
    """Every scannable thing, discovered fresh each run (new CTs are picked up automatically)."""
    return hosts.targets()


# ── scanners ─────────────────────────────────────────────────────────────────
def remote(t, cmd, binary=False, timeout=300):
    """Read-only access as the configured user (package DBs are world-readable)."""
    return hosts.remote(t, cmd, timeout=timeout, binary=binary)


def sh_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


_OSV = None


def osv_client():
    global _OSV
    if _OSV is None:
        _OSV = osv.OSV(DB)
    return _OSV


def os_identity(files):
    """files: {relpath: text} → (ecosystem, label, [(src, srcver, bin, binver)])."""
    osr = osv.kv(files.get("etc/os-release") or files.get("usr/lib/os-release") or "")
    eco, label = osv.ecosystem(osr, (files.get("etc/alpine-release") or "").strip())
    if files.get("lib/apk/db/installed"):
        entries = osv.parse_apk(files["lib/apk/db/installed"])
    else:
        entries = osv.parse_dpkg(files.get("var/lib/dpkg/status") or "")
    return eco, label, entries


def scan_os(t, kev):
    rc, tarb, se = remote(t, "tar czhf - --ignore-failed-read -C / " + " ".join(PKG_FILES) + " 2>/dev/null; true",
                          binary=True, timeout=120)
    if not tarb:
        raise RuntimeError(f"could not read package DB ({(se or b'')[-120:]!r})")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(tarb)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                files[m.name.lstrip("./")] = tf.extractfile(m).read().decode("utf-8", "replace")
    eco, label, entries = os_identity(files)
    if not entries:
        raise RuntimeError("OS not identified (no dpkg/apk DB?)")
    if not eco:
        raise RuntimeError(f"{label}: OSV has no advisory feed for this OS")
    rows = osv.match(osv_client(), osv.os_packages(eco, entries), kev)
    rc, facts, _ = remote(t, FACTS, timeout=120)
    f = (facts or "").split()
    extra = {"upgradable": int(f[0]) if f and f[0].isdigit() else None,
             "reboot_required": int(f[1]) if len(f) > 1 and f[1].isdigit() else None,
             "kernel": f[2] if len(f) > 2 else None, "newest_kernel": f[3] if len(f) > 3 and f[3] != "-" else None}
    if t["kind"] == "node" and extra["kernel"] and extra["newest_kernel"] and extra["newest_kernel"] != extra["kernel"]:
        extra["reboot_required"] = 1          # Proxmox rarely writes reboot-required; a newer kernel on disk is the tell
    return label, rows, extra, len(entries)


def image_packages(files):
    """One image's collected files → (match() input, label, unread_go)."""
    osf = {k[3:]: v for k, v in files.items() if k.startswith("os/")}
    named = {"etc_os-release": "etc/os-release", "usr_lib_os-release": "usr/lib/os-release",
             "etc_alpine-release": "etc/alpine-release", "var_lib_dpkg_status": "var/lib/dpkg/status",
             "lib_apk_db_installed": "lib/apk/db/installed"}
    text = {named[k]: v.decode("utf-8", "replace") for k, v in osf.items() if k in named}
    statusd = [v.decode("utf-8", "replace") for k, v in osf.items() if k.startswith("statusd_")]
    if statusd and not text.get("var/lib/dpkg/status"):
        text["var/lib/dpkg/status"] = "\n\n".join(statusd)
    eco, label, entries = os_identity(text)
    pkgs = osv.os_packages(eco, entries) if eco else []
    unread = 0
    for k, v in files.items():
        kind = k.split("/", 1)[0]
        body = v.split(b"\n", 1)[1] if b"\n" in v else b""
        if kind == "py":
            r = osv.parse_pymeta(body.decode("utf-8", "replace"))
            if r:
                pkgs.append(("PyPI", r[0], r[1], r[0], r[1]))
        elif kind == "npm":
            r = osv.parse_npm(body.decode("utf-8", "replace"))
            if r:
                pkgs.append(("npm", r[0], r[1], r[0], r[1]))
        elif kind == "go":
            gover, deps = osv.parse_gobuild(body)
            if not gover:
                unread += 1
                continue
            gv = gover.split()[0].removeprefix("go")
            pkgs.append(("Go", "stdlib", gv, "stdlib", gv))
            pkgs += [("Go", m, ver, m, ver) for m, ver in deps]
        elif kind == "rust":
            pkgs += [("crates.io", c, ver, c, ver) for c, ver in osv.parse_rustdeps(body)]
    if not entries and not eco:
        label = "no OS packages"
    return sorted(set(pkgs)), label, unread


def scan_images(t, kev):
    rc, tarb, se = hosts.remote(t, "python3 -", timeout=1800, binary=True, root=True, stdin=COLLECTOR.encode())
    if not tarb:
        raise RuntimeError(f"collector: {(se or b'').decode('utf-8', 'replace').strip()[-160:] or 'no output'}")
    images, errs = {}, []
    with tarfile.open(fileobj=io.BytesIO(tarb), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            data = tf.extractfile(m).read()
            if m.name == "ERRORS":
                errs += [l for l in data.decode().splitlines() if l]
                continue
            n, _, rest = m.name.partition("/")
            images.setdefault(n, {})[rest] = data
    rows, notes = [], []
    for n, files in sorted(images.items(), key=lambda x: int(x[0])):
        img = files.pop("IMAGE", b"?").decode()
        pkgs, label, unread = image_packages(files)
        rows += osv.match(osv_client(), pkgs, kev, image=img)
        if unread:
            notes.append(f"{img}: {unread} pre-1.18 Go binaries not read")
    return rows, errs + notes, len(images) + len([e for e in errs])


# Vendor firmware with no package DB: how to read the running version, and where the vendor publishes releases.
FIRMWARE = {
    "zimaos": {"label": "ZimaOS", "version_cmd": "grep -E '^VERSION=' /etc/os-release",
               "releases": "IceWhaleTech/ZimaOS", "update_hint": "ZimaOS settings → update"},
}


def firmware(t):
    """(label, current, latest, note) for a `firmware:` host. Unknown kinds → (label, None, None, note)."""
    kind = (t.get("firmware") or "").lower()
    spec = FIRMWARE.get(kind)
    if not spec:
        return kind or "firmware", None, None, f"no firmware check for '{kind}' — skipped"
    rc, so, _ = hosts.remote(t, spec["version_cmd"], timeout=30)
    cur = (so or "").strip().split("=", 1)[-1].strip('"')
    latest, note = None, ""
    try:
        rel = requests.get(f"https://api.github.com/repos/{spec['releases']}/releases?per_page=30", timeout=20).json()
        # some vendors tag betas as normal releases (1.8.0-beta2 is NOT prerelease) — stable = no '-' suffix
        stable = [r["tag_name"] for r in rel if not r.get("prerelease") and "-" not in r["tag_name"]]
        latest = stable[0] if stable else None
    except Exception as e:  # noqa: BLE001
        note = f"latest unknown ({type(e).__name__})"
    return spec["label"], cur, latest, note


# ── store ────────────────────────────────────────────────────────────────────
def store(con, t, os_, rows, status, note, extra=None, pkgs=None):
    extra = extra or {}
    con.execute("delete from vulns where target=?", (t["target"],))
    con.executemany("insert or replace into vulns(target,vid,pkg,installed,fixed,severity,title,kev,status,image,"
                    "descr,url) values(?,?,?,?,?,?,?,?,?,?,?,?)", [(t["target"],) + r for r in rows])
    fix = [r for r in rows if r[3]]
    con.execute("""insert or replace into vuln_targets(target,kind,name,node,vmid,os,last_scan,status,note,pkgs,
                   upgradable,reboot_required,kernel,newest_kernel,patchable,n_total,n_fixable,n_crit_fix,n_high_fix,n_kev)
                   values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (t["target"], t["kind"], t["name"], t["node"], t["vmid"], os_, now(), status, note, pkgs,
                 extra.get("upgradable"), extra.get("reboot_required"), extra.get("kernel"), extra.get("newest_kernel"),
                 t["patchable"], len(rows), len(fix), sum(1 for r in fix if r[4] == "CRITICAL"),
                 sum(1 for r in fix if r[4] == "HIGH"), sum(1 for r in rows if r[6])))
    con.commit()


def scan_one(con, t, kev):
    try:
        if t["kind"] in ("node", "ct"):
            os_, rows, extra, pkgs = scan_os(t, kev)
            note = ""
            if t["kind"] == "ct":
                # An LXC container runs the HOST's kernel: kernel CVEs matched against linux-libc-dev / headers
                # inside it are not exploitable there (one CT showed 2 'KEV' this way on 2026-10-07).
                k = [r for r in rows if KERNEL_PKG.match(r[1])]
                rows = [r for r in rows if not KERNEL_PKG.match(r[1])]
                if k:
                    note = f"{len(k)} kernel-package CVEs ignored (LXC runs the host kernel)"
            else:
                note = ("Proxmox kernel (proxmox-kernel-*) is NOT covered by Debian advisories — kernel CVEs are a "
                        "blind spot here; keep the node on the latest pve kernel and reboot into it")
            store(con, t, os_, rows, "ok", note, extra, pkgs)
        elif t["kind"] == "images":
            rows, errs, n = scan_images(t, kev)
            # a container runs the host's kernel too: linux-libc-dev/headers CVEs inside an image are not reachable
            # (462 of 600 "critical with a fix" on CT104 were these, 2026-10-10)
            k = sum(1 for r in rows if KERNEL_PKG.match(r[1]))
            rows = [r for r in rows if not KERNEL_PKG.match(r[1])]
            if k:
                errs = errs + [f"{k} kernel-package CVEs ignored (containers run the host kernel)"]
            done = n - sum(1 for e in errs if "not readable" in e)
            real = [e for e in errs if "kernel-package" not in e]
            store(con, t, f"{done}/{n} running images", rows, "ok" if not real else "partial", "; ".join(errs)[:400])
        elif t["kind"] == "firmware":
            label, cur, latest, note = firmware(t)
            if cur is None and latest is None and note.startswith("no firmware check"):
                store(con, t, label, [], "skipped", note)
                return "skipped"
            behind = bool(latest and cur and latest.lstrip("v") != cur.lstrip("v"))
            hint = FIRMWARE.get((t.get("firmware") or "").lower(), {}).get("update_hint", "vendor updater")
            store(con, t, f"{label} {cur}", [], "ok",
                  (f"latest {latest} — UPDATE AVAILABLE ({hint})" if behind else
                   f"latest {latest} — up to date" if latest else note) +
                  " · no package DB, so no per-CVE view; firmware version is the only lever")
        elif t["kind"] in ("host", "local") and t.get("os_scan") is False:
            store(con, t, "appliance OS", [], "skipped",
                  "no package DB on this OS — covered by its firmware check and Docker image scan")
            return "skipped"
        elif t["kind"] in ("host", "local"):
            ok, err = hosts.check(t)
            if not ok:
                store(con, t, "", [], "blind",
                      f"no non-interactive SSH access from warden ({err or 'key not accepted'}) — not scanned")
                return "blind"
            os_, rows, extra, pkgs = scan_os(t, kev)
            store(con, t, os_, rows, "ok", "", extra, pkgs)
        return "ok"
    except Exception as e:  # noqa: BLE001 — one dead box must not stop the estate scan
        prev = con.execute("select os from vuln_targets where target=?", (t["target"],)).fetchone()
        con.execute("""insert into vuln_targets(target,kind,name,node,vmid,os,last_scan,status,note,patchable)
                       values(?,?,?,?,?,?,?,?,?,?) on conflict(target) do update set
                       last_scan=excluded.last_scan, status='error', note=excluded.note""",
                    (t["target"], t["kind"], t["name"], t["node"], t["vmid"], prev[0] if prev else "", now(), "error",
                     str(e)[:300], t["patchable"]))
        con.commit()
        return f"error: {e}"


def alert_new(con, before):
    after = {(r[0], r[1]) for r in con.execute(
        "select target, vid from vulns where kev=1 or (severity='CRITICAL' and fixed!='')")}
    new = sorted(after - before)
    if not new:
        return
    names = dict(con.execute("select target, name from vuln_targets"))
    detail = {}
    for tgt, vid in new:
        r = con.execute("select pkg, severity, kev, fixed from vulns where target=? and vid=? limit 1", (tgt, vid)).fetchone()
        detail.setdefault(tgt, []).append(f"{'🔥KEV ' if r[2] else ''}{vid} {r[0]}{' → ' + r[3] if r[3] else ''}")
    lines = [f"**{names.get(t, t)}** (`{t}`): " + ", ".join(v[:6]) + (f" +{len(v) - 6} more" if len(v) > 6 else "")
             for t, v in detail.items()]
    msg = "🩹 **New must-fix vulnerabilities** (known-exploited or critical with a fix)\n" + "\n".join(lines[:15]) + \
          "\nOpen warden → Vulnerabilities to queue a patch."
    if not notify.send(msg[:1990]):
        log("alert not sent")


def main():
    a = sys.argv[1:]
    con = db()
    if a and a[0] == "--list":
        for r in con.execute("select target,name,status,os,n_total,n_fixable,n_crit_fix,n_kev,last_scan,note "
                             "from vuln_targets order by target"):
            print(" | ".join("" if x is None else str(x) for x in r))
        return 0
    kev = kev_set()
    before = {(r[0], r[1]) for r in con.execute(
        "select target, vid from vulns where kev=1 or (severity='CRITICAL' and fixed!='')")}
    first_run = con.execute("select count(*) from vuln_targets").fetchone()[0] == 0
    # the first scan after the trivy → OSV switch finds fresher fixes; one summary, not dozens of "new" alerts
    switched = con.execute("select count(*) from sqlite_master where name='osv_vulns'").fetchone()[0] == 0 or \
        con.execute("select count(*) from osv_vulns").fetchone()[0] == 0
    ts = targets()
    if a:
        ts = [t for t in ts if t["target"] == a[0]]
        if not ts:
            sys.exit(f"unknown target {a[0]}")
    for t in ts:
        t0 = time.time()
        r = scan_one(con, t, kev)
        log(f"{t['target']:<22} {t['name']:<24} {r}  ({time.time() - t0:.0f}s)")
    # retire targets that no longer exist (a destroyed CT must not linger as 'vulnerable')
    if not a:
        live = {t["target"] for t in ts}
        for (tgt,) in con.execute("select target from vuln_targets").fetchall():
            if tgt not in live:
                con.execute("delete from vulns where target=?", (tgt,))
                con.execute("delete from vuln_targets where target=?", (tgt,))
        con.commit()
    if switched and not first_run and not a:
        after = con.execute("select count(distinct target||vid) from vulns where kev=1 or "
                            "(severity='CRITICAL' and fixed!='')").fetchone()[0]
        notify.send(f"🩹 warden now matches vulnerabilities against OSV.dev instead of trivy. Must-fix (known-exploited "
                    f"or critical with a fix): {len(before)} before → {after} now. Most of the change is fixes newer "
                    "than trivy's database knew; open warden → Vulnerabilities for the list.")
    elif not first_run and not a:
        alert_new(con, before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
