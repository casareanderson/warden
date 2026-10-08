#!/usr/bin/env python3
"""vulnscan.py — estate-wide vulnerability inventory for warden (built 2026-10-07). No LLM.

  vulnscan.py              scan everything (timer: daily 03:30), alert on new KEV / new fixable CRITICAL
  vulnscan.py <target>     scan one target (e.g. ct:101, node:10.0.0.2, img:nas) — used after a patch
  vulnscan.py --list       show targets + last results

HOW (nothing is installed on the scanned boxes):
  Debian/Ubuntu/Alpine boxes — copy ONLY the package DB + OS-identity files (dpkg status, os-release,
  lsb-release, debian_version, apk db) into a temp tree on the warden box and run `trivy rootfs` on it.
  Verified 2026-10-07: identical to scanning the box's real / (4,592 = 4,592 findings, 0 differences).
  Docker images — the verified trivy binary is copied to the docker host's /tmp and run in CLIENT mode
  against a `trivy-server` (warden.yml `vuln.server`, token in `vuln.token_file`), only for images of
  RUNNING containers.
  Vendor-firmware hosts (`firmware:` on a host, e.g. zimaos) — no package DB; tracked as a firmware version
  vs the vendor's latest release.

Targets come from wlib.hosts (warden.yml `hosts:`), so a new box is a config edit.

Trivy: v0.74.0, checksum + Sigstore-verified (Aqua's release workflow @ tag) because v0.69.4 and the
v0.69.5/6 Docker images were malicious (CVE-2026-33634). Never `docker pull aquasec/trivy`.
Priority = CISA KEV (known exploited) > CRITICAL with fix > HIGH with fix. Raw counts are mostly
"affected, no fix yet" upstream noise (one box: 4,592 CVEs, 0 fixable) — the UI leads with fixable/KEV.
"""
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
TRIVY = config.get("vuln.trivy")
CACHE = config.get("vuln.cache")
KEV_FILE = str(config.DATA / "kev.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SSH = hosts.SSH
PKG_FILES = ["var/lib/dpkg/status", "etc/os-release", "usr/lib/os-release", "etc/lsb-release",
             "etc/debian_version", "lib/apk/db/installed", "etc/alpine-release"]
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


def trivy_json(path_or_args, timeout=600):
    rc, so, se = run([TRIVY] + path_or_args + ["--quiet", "--scanners", "vuln", "--format", "json",
                                                "--cache-dir", CACHE, "--skip-db-update"], timeout=timeout)
    if rc != 0:
        raise RuntimeError((se or "trivy failed").strip().splitlines()[-1][:200])
    return json.loads(so)


def scan_os(t):
    rc, tarb, se = remote(t, "tar czhf - --ignore-failed-read -C / " + " ".join(PKG_FILES) + " 2>/dev/null; true",
                          binary=True, timeout=120)
    if not tarb:
        raise RuntimeError(f"could not read package DB ({(se or b'')[-120:]!r})")
    tmp = tempfile.mkdtemp(prefix="vs-")
    try:
        with tarfile.open(fileobj=io.BytesIO(tarb)) as tf:
            tf.extractall(tmp, filter="data")
        derived = normalise_derivative(tmp)
        d = trivy_json(["rootfs", "--pkg-types", "os", tmp])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rc, facts, _ = remote(t, FACTS, timeout=120)
    f = (facts or "").split()
    extra = {"upgradable": int(f[0]) if f and f[0].isdigit() else None,
             "reboot_required": int(f[1]) if len(f) > 1 and f[1].isdigit() else None,
             "kernel": f[2] if len(f) > 2 else None, "newest_kernel": f[3] if len(f) > 3 and f[3] != "-" else None}
    if t["kind"] == "node" and extra["kernel"] and extra["newest_kernel"] and extra["newest_kernel"] != extra["kernel"]:
        extra["reboot_required"] = 1          # Proxmox rarely writes reboot-required; a newer kernel on disk is the tell
    os_ = d.get("Metadata", {}).get("OS") or {}
    if not os_.get("Family") or os_.get("Family") == "none":
        raise RuntimeError("OS not identified (no dpkg/apk DB?)")
    pkgs = sum(len(r.get("Packages") or []) for r in d.get("Results", [])) or None
    label = f"{os_.get('Family')} {os_.get('Name')}"
    return (f"{derived} (scanned as {label})" if derived else label), d, extra, pkgs


def normalise_derivative(root):
    """Ubuntu derivatives (Pop!_OS etc.) call themselves ID=pop / DISTRIB_ID=Pop, which trivy does not know;
    it then falls back to debian_version ('bookworm/sid') and matches NOTHING — a false clean bill of health
    (a Pop!_OS box read 0 CVEs on 2026-10-07). Rewrite the identity to the Ubuntu base the packages come from."""
    def kv(path):
        try:
            return dict(l.strip().split("=", 1) for l in open(path) if "=" in l)
        except OSError:
            return {}
    osr = kv(os.path.join(root, "etc/os-release")) or kv(os.path.join(root, "usr/lib/os-release"))
    ident = osr.get("ID", "").strip('"')
    like = osr.get("ID_LIKE", "").strip('"').split()
    ver = osr.get("VERSION_ID", "").strip('"')
    if ident in ("ubuntu", "debian", "alpine", "") or "ubuntu" not in like or not ver:
        return None
    code = osr.get("UBUNTU_CODENAME", osr.get("VERSION_CODENAME", "")).strip('"')
    for rel in ("etc/os-release", "usr/lib/os-release"):
        p = os.path.join(root, rel)
        if os.path.exists(p):
            os.remove(p)
    open(os.path.join(root, "etc/os-release"), "w").write(f'ID=ubuntu\nVERSION_ID="{ver}"\nVERSION_CODENAME={code}\n')
    open(os.path.join(root, "etc/lsb-release"), "w").write(f"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE={ver}\nDISTRIB_CODENAME={code}\n")
    dv = os.path.join(root, "etc/debian_version")
    if os.path.exists(dv):
        os.remove(dv)
    return f"{ident} {ver}"


TRIVY_REMOTE = "/tmp/warden-trivy"


def scan_images(t):
    tok = open(config.get("vuln.token_file")).read().strip()
    want = run([TRIVY, "--version"])[1].split()[1]

    def rsh(cmd, timeout=900):
        return hosts.remote(t, cmd, timeout=timeout)
    rc, so, _ = rsh(f"{TRIVY_REMOTE} --version 2>/dev/null | head -1")
    if want not in (so or ""):
        ok, err = hosts.push(t, TRIVY, TRIVY_REMOTE)
        if not ok:
            raise RuntimeError(f"copy trivy to {t['name']}: {err[:120]}")
    rc, so, se = rsh("docker ps --format '{{.Image}}' | sort -u")
    if rc != 0:
        raise RuntimeError(f"docker ps: {se.strip()[:120]}")
    images = [i for i in so.split() if i]
    results, errs = [], []
    server = config.get("vuln.server")
    for img in images:
        cmd = (f"chmod 755 {TRIVY_REMOTE}; TRIVY_TOKEN={tok} {TRIVY_REMOTE} image --server {server} "
               f"--token-header Trivy-Token --scanners vuln --quiet --format json --timeout 10m {sh_quote(img)}")
        rc, so, se = rsh(cmd, timeout=900)
        if rc != 0 or not so.strip().startswith("{"):
            errs.append(f"{img}: {(se or 'no output').strip().splitlines()[-1][:80] if (se or '').strip() else 'failed'}")
            continue
        results.append((img, json.loads(so)))
    return results, errs, len(images)


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
def rows_from(d, kev, image=""):
    out = {}
    for r in d.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"], image)
            out[key] = (v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion", ""), v.get("FixedVersion", ""),
                        v.get("Severity", "UNKNOWN"), (v.get("Title") or "")[:200], int(v["VulnerabilityID"] in kev),
                        v.get("Status", ""), image)
    return list(out.values())


def store(con, t, os_, rows, status, note, extra=None, pkgs=None):
    extra = extra or {}
    con.execute("delete from vulns where target=?", (t["target"],))
    con.executemany("insert or replace into vulns(target,vid,pkg,installed,fixed,severity,title,kev,status,image) "
                    "values(?,?,?,?,?,?,?,?,?,?)", [(t["target"],) + r for r in rows])
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
            os_, d, extra, pkgs = scan_os(t)
            rows, note = rows_from(d, kev), ""
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
            res, errs, n = scan_images(t)
            rows = [r for img, d in res for r in rows_from(d, kev, img)]
            store(con, t, f"{len(res)}/{n} running images", rows, "ok" if not errs else "partial", "; ".join(errs)[:400])
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
        elif t["kind"] in ("host", "local"):
            ok, err = hosts.check(t)
            if not ok:
                store(con, t, "", [], "blind",
                      f"no non-interactive SSH access from warden ({err or 'key not accepted'}) — not scanned")
                return "blind"
            os_, d, extra, pkgs = scan_os(t)
            store(con, t, os_, rows_from(d, kev), "ok", "", extra, pkgs)
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
    rc, _, se = run([TRIVY, "image", "--download-db-only", "--cache-dir", CACHE, "--quiet"], timeout=900)
    if rc != 0:
        log(f"DB update failed: {se.strip()[-200:]} — scanning with the cached DB")
    kev = kev_set()
    before = {(r[0], r[1]) for r in con.execute(
        "select target, vid from vulns where kev=1 or (severity='CRITICAL' and fixed!='')")}
    first_run = con.execute("select count(*) from vuln_targets").fetchone()[0] == 0
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
    if not first_run and not a:
        alert_new(con, before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
