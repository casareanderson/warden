#!/usr/bin/env python3
"""patcher.py — owner-approved patching for warden (built 2026-10-07). No LLM.

Flow (owner's choice 2026-10-07: "Button + Discord ✅", "Full upgrade + reboot"):
  1. warden's Patch button drops data/patch-queue/<id>.json — the web page can NEVER run a command.
  2. `patcher.py run` (timer, 2 min) turns each request into a PLAN: `apt-get -s full-upgrade` on the box,
     posted to the alert channel with ✅/❌ (packages, removals, CVEs it fixes, snapshot, reboot policy);
     the dashboard can approve it too (wlib.notify keeps a local approvals ledger).
  3. Owner ✅ → LXC: Proxmox snapshot `warden-prepatch-<stamp>` first → apt full-upgrade (non-interactive,
     keep existing config files) → reboot IF required → rescan → reply with before/after + rollback command.
     ❌ → dropped. Unanswered 24 h → expired.

Hard rules:
  - Proxmox NODES are upgraded but NEVER rebooted automatically (one reboot takes every guest down; a node on
    slow disks can have a 15-min IO storm after boot). The reply says when a reboot is needed.
  - A plan that REMOVES proxmox-ve / pve-manager / pve-kernel meta, or any `systemd`/`openssh-server`, is refused.
  - One job at a time. warden's own container (`estate.self_target`) reboots via a delayed `pct reboot` on its
    node, after the reply is sent.
  - Docker images and vendor firmware are not patchable from here (image pulls / vendor updater).
  - A plain host's sudo password is the secret named by its `sudo_secret`, read at run time and sent over
    stdin — never on a command line.
"""
import fcntl
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
QUEUE = config.DATA / "patch-queue"
LOCK = str(config.DATA / ".patcher.lock")
LOG = config.get("patch.log")
EXPIRE_H = int(config.get("patch.expire_hours", 24))
SNAP_KEEP_DAYS = int(config.get("patch.snapshot_keep_days", 7))
SSH = hosts.SSH
NEVER_REMOVE = re.compile(r"^(proxmox-ve|pve-manager|pve-kernel|proxmox-kernel-helper|systemd|openssh-server|sudo)$")
APT_ENV = "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a"
APT_OPTS = "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"


def now():
    return datetime.now(timezone.utc)


def iso(t=None):
    return (t or now()).strftime("%Y-%m-%d %H:%M:%S")


def log(m):
    line = f"{iso()} {m}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists patch_jobs(
        id integer primary key, target text, name text, status text, requested_by text, requested text,
        plan text, n_pkgs integer, n_remove integer, message_id text, decided text, snapshot text,
        result text, before_fix integer, after_fix integer, reboot text, finished text);
    """)
    cols = {r[1] for r in con.execute("pragma table_info(patch_jobs)")}
    for col in ("timing text", "run_after text", "timing_why text"):
        if col.split()[0] not in cols:
            con.execute(f"alter table patch_jobs add column {col}")
    return con


def sh_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def is_self(t):
    return bool(hosts.self_target()) and t["target"] == hosts.self_target()


def target_info(con, target):
    if target.startswith("ctr:"):                       # ctr:<docker host>:<container>, e.g. ctr:nas:npm
        _, host, cname = target.split(":", 2)
        host = "img:" + host
        a = con.execute("select * from img_advice where host=? and container=?", (host, cname)).fetchone()
        if not a or a["action"] not in ("recreate", "pull"):
            raise ValueError(f"{target} is not an automatic container update")
        return {"target": target, "kind": "container", "name": f"{cname} ({host.split(':', 1)[1]})",
                "host": host, "container": cname, "workdir": a["workdir"], "service": a["service"],
                "action": a["action"], "image": a["image"], "kev": a["kev"], "crit": a["crit_fix"],
                "n_fixable": a["fixable"], "patchable": 1}
    r = con.execute("select * from vuln_targets where target=?", (target,)).fetchone()
    if not r or not r["patchable"]:
        raise ValueError(f"{target} is not a patchable target")
    t = dict(r)
    live = hosts.find(target)                           # how to reach it comes from the inventory, not the DB
    if not live:
        raise ValueError(f"{target} is no longer in the host inventory")
    for k in ("ssh", "sudo_secret", "local", "kind", "node", "vmid"):
        if k in live:
            t[k] = live[k]
    return t


def docker_sh(t, cmd, timeout=1800):
    """Run on the container's docker host (a docker-group user over SSH, or `pct exec` into a docker LXC)."""
    rc, so, se = hosts.remote(hosts.docker_host(t["host"]), cmd, timeout=timeout)
    return rc, (so or "") + (se or "")


def remote(t, cmd, timeout=3600, sudo=False):
    """Run as root on the target. Returns (rc, combined output)."""
    if t["kind"] not in ("node", "ct", "host", "local"):
        raise ValueError(t["kind"])
    rc, so, se = hosts.remote(t, cmd, timeout=timeout, root=True)
    return rc, (so or "") + (se or "")


def node_ssh(t, cmd, timeout=600):
    """A command on the Proxmox node that hosts `t` (snapshots, reboots). Returns CompletedProcess-like."""
    rc, so, se = hosts.run(SSH + [t["ssh"], cmd], timeout=timeout)
    return subprocess.CompletedProcess(cmd, rc, so, se)


# ── timing: an optional advisor picks NOW vs TONIGHT; it only advises — the owner still ✅s, and ⚡ overrides to
#    "now". Without an advisor the rule below decides.
NOW_REACT = notify.NOW
REBOOTY = re.compile(r"^(linux-image|linux-modules|proxmox-kernel|pve-kernel|libc6|libc-bin|systemd|dbus|openssl|"
                     r"libssl|lxc|pve-container|qemu-server|openssh-server|nvidia)")


def night():
    h, _, m = str(config.get("patch.night") or "02:30").partition(":")
    return int(h), int(m or 0)


def tz():
    from zoneinfo import ZoneInfo
    return ZoneInfo(config.get("estate.timezone") or "UTC")


def advisor():
    name = config.get("patch.advisor")
    if not name:
        return None
    try:
        if config.get("patch.advisor_path"):
            sys.path.insert(0, config.get("patch.advisor_path"))
        import importlib
        return importlib.import_module(name)
    except Exception:  # noqa: BLE001 - an advisor is optional; its absence must never block a patch
        return None


def busy_fact(t):
    bp = config.get("patch.busy_probe") or {}
    if not bp or bp.get("target") != t["target"]:
        return ""
    try:
        return f"Active work on this box right now: {json.load(open(bp['json_file'])).get(bp.get('key', 'active'))}"
    except Exception:  # noqa: BLE001
        return ""


def next_night():
    n = datetime.now(tz())
    nh, nm = night()
    t = n.replace(hour=nh, minute=nm, second=0, microsecond=0)
    if t <= n:
        t += timedelta(days=1)
    return t.astimezone(timezone.utc)


def timing_rule(t, inst, fixes):
    """The default decision: urgent security → now; reboot-y packages or a core service → tonight; else now."""
    rebooty = sorted({n for n, *_ in inst if REBOOTY.match(n)})
    kev, crit = fixes[2] or 0, fixes[1] or 0
    core = hosts.core()
    rule = ("now" if (kev or crit) else "tonight" if (rebooty or t["target"] in core) else "now")
    why_rule = ("security fix is urgent" if (kev or crit) else
                f"reboot/restart likely ({', '.join(rebooty[:4])})" if rebooty else
                "core service, avoid daytime disruption" if t["target"] in core else "low-impact update")
    return rule, why_rule, rebooty


def decide_timing(t, inst, remv, fixes):
    local = datetime.now(tz())
    nh, nm = night()
    rule, why_rule, rebooty = timing_rule(t, inst, fixes)
    kev, crit = fixes[2] or 0, fixes[1] or 0
    facts = (f"Box: {t['name']} ({t['target']}). Role: {hosts.roles().get(t['target'], 'unknown role')}.\n"
             f"Upgrade: {len(inst)} packages, {len(remv)} removals. Packages likely to force a reboot or restart core "
             f"services: {', '.join(rebooty) or 'none'}.\n"
             f"Security: {kev} known-exploited (CISA KEV) and {crit} critical CVEs fixed by this upgrade.\n"
             f"Local time now: {local:%A %H:%M} ({local.tzname()}). The quiet window is {nh:02d}:{nm:02d}, when nobody "
             f"uses the services. {busy_fact(t)}\nA container is snapshotted first and can be rolled back in seconds.")
    adv = advisor()
    label = (config.get("patch.advisor") or "advisor").rsplit(".", 1)[-1].capitalize()
    d = None
    if adv is not None:
        try:
            d = adv.choose(facts,
                           "Decide WHEN to apply this approved package upgrade. Prefer 'tonight' when it would restart or "
                           "reboot something people rely on during the day, or interrupt active work. Prefer 'now' when "
                           "the update is low-impact, or when known-exploited/critical security fixes make waiting riskier "
                           "than a short daytime blip.",
                           {"now": "apply as soon as the owner approves", "tonight": f"hold until {nh:02d}:{nm:02d} local"},
                           caller="warden-patcher")
        except Exception:  # noqa: BLE001
            d = None
    if d and (d.confidence is None or d.confidence >= 0.6):
        p = (d.probs or {}).get(d.value)
        return d.value, f"{label}{f' p={p:.2f}' if isinstance(p, (int, float)) else ''} — {why_rule}"
    if adv is None:
        return rule, f"rule — {why_rule}"
    return rule, f"rule ({label} {'unsure' if d else 'unavailable'}) — {why_rule}"


# ── 1. queue → plan ──────────────────────────────────────────────────────────
def intake(con):
    QUEUE.mkdir(parents=True, exist_ok=True)
    for f in sorted(QUEUE.glob("*.json")):
        try:
            req = json.loads(f.read_text())
            t = target_info(con, req["target"])
        except Exception as e:  # noqa: BLE001
            log(f"bad request {f.name}: {e}"); f.rename(f.with_suffix(".rejected")); continue
        busy = con.execute("select 1 from patch_jobs where target=? and status in "
                           "('planning','pending','approved','running')", (t["target"],)).fetchone()
        f.unlink()
        if busy:
            log(f"{t['target']}: request ignored, a job is already open"); continue
        con.execute("insert into patch_jobs(target,name,status,requested_by,requested,before_fix) values(?,?,?,?,?,?)",
                    (t["target"], t["name"], "planning", req.get("by", "?"), iso(), t.get("n_fixable")))
        con.commit()


def make_plan_container(con, job, t):
    wd, svc = t["workdir"], t["service"]
    rc, out = docker_sh(t, f"test -r {wd}/docker-compose.yml -o -r {wd}/compose.yml -o -r {wd}/docker-compose.yaml "
                           f"-o -r {wd}/compose.yaml && echo READABLE", timeout=60)
    if "READABLE" not in out:
        msg = (f"🐳 **Container update: {t['name']}** — 🛑 REFUSED: its compose file in `{wd}` is not readable by the "
               f"automation account (e.g. a root-only CasaOS app). Update it from CasaOS / by hand.")
        notify.send(msg)
        con.execute("update patch_jobs set status='refused', plan=?, finished=? where id=?", (msg, iso(), job["id"]))
        con.commit(); return
    steps = (f"`docker compose pull {svc}` then " if t["action"] == "pull" else "") + \
        f"`docker compose up -d --no-deps {svc}` in `{wd}`"
    timing, why = decide_timing({"target": t["target"], "name": t["name"]}, [(svc, "", "")], [],
                                (None, t["crit"], t["kev"]))
    run_after = iso() if timing == "now" else iso(next_night())
    msg = "\n".join([f"🐳 **Container update: {t['name']}** — requested by {job['requested_by']}",
                     f"• image `{t['image']}` · fixes up to {t['kev']} known-exploited / {t['crit']} critical CVE(s)",
                     f"• steps: {steps} — re-creates ONLY this container, same compose settings and volumes",
                     "• rollback: the previous image stays on disk; re-tag it and `up -d` again",
                     f"⏱ timing: **{'as soon as approved' if timing == 'now' else 'tonight ' + run_after[11:16] + ' UTC'}** ({why})"])
    mid = notify.post(msg + f"\n✅ = approve with that timing · {NOW_REACT} = approve and run NOW · ❌ = cancel")
    notify.react(mid, notify.APPROVE); notify.react(mid, NOW_REACT); notify.react(mid, notify.REJECT)
    con.execute("update patch_jobs set status='pending', plan=?, n_pkgs=1, n_remove=0, message_id=?, timing=?, run_after=?, "
                "timing_why=? where id=?", (msg, mid, timing, run_after, why, job["id"]))
    con.commit()


def execute_container(con, job, t):
    mid = job["message_id"]
    con.execute("update patch_jobs set status='running', decided=? where id=?", (iso(), job["id"])); con.commit()
    wd, svc, c = t["workdir"], t["service"], t["container"]
    before = docker_sh(t, f"docker inspect -f '{{{{.Image}}}}' {c}", 60)[1].strip()
    cmd = f"cd {wd} && " + (f"docker compose pull {svc} && " if t["action"] == "pull" else "") + \
        f"docker compose up -d --no-deps {svc}"
    rc, out = docker_sh(t, cmd)
    if rc != 0:
        raise RuntimeError(f"compose failed (rc {rc}): {out.strip()[-300:]}")
    time.sleep(20)
    st = docker_sh(t, f"docker inspect -f '{{{{.State.Status}}}} {{{{.Image}}}}' {c}", 60)[1].split()
    ok = bool(st) and st[0] == "running"
    changed = len(st) > 1 and st[1] != before
    result = (f"{'✅' if ok else '🛑'} **{t['name']}** re-created — state `{st[0] if st else '?'}`, "
              f"image {'updated' if changed else 'UNCHANGED (was already current?)'}."
              + ("" if ok else f" Rollback: `docker tag {before[:19]} {t['image']}` then `docker compose up -d {svc}` in {wd}"))
    con.execute("update patch_jobs set status=?, result=?, finished=? where id=?",
                ("done" if ok else "failed", result, iso(), job["id"])); con.commit()
    notify.post(result, reply_to=mid)
    subprocess.run([sys.executable, os.path.join(HERE, "images.py")], capture_output=True, timeout=300)


def make_plan(con, job):
    t = target_info(con, job["target"])
    if t["kind"] == "container":
        return make_plan_container(con, job, t)
    rc, out = remote(t, "apt-get update -qq >/dev/null 2>&1; apt-get -s full-upgrade", timeout=900)
    if rc != 0:
        raise RuntimeError(f"dry run failed: {out.strip().splitlines()[-1][:200] if out.strip() else rc}")
    inst = re.findall(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+)", out, re.M)
    remv = re.findall(r"^Remv (\S+)", out, re.M)
    bad = [p for p in remv if NEVER_REMOVE.match(p)]
    fixes = con.execute("select count(distinct vid), sum(severity='CRITICAL'), sum(kev) from vulns "
                        "where target=? and fixed!=''", (t["target"],)).fetchone()
    reboot = ("NEVER automatic (Proxmox node) — you'll be told if one is needed" if t["kind"] == "node" else
              "automatic if the upgrade requires it" + (" (this is warden's own box: ~1 min blip)"
                                                       if is_self(t) else ""))
    snap = "Proxmox snapshot first (rollback in seconds)" if t["kind"] == "ct" else \
        "⚠️ none possible (physical host) — apt only"
    lines = [f"🩹 **Patch plan: {t['name']}** (`{t['target']}`) — requested by {job['requested_by']}",
             f"• {len(inst)} package(s) to upgrade/install, {len(remv)} to REMOVE",
             f"• fixes {fixes[0] or 0} known CVE(s) on this box ({fixes[1] or 0} critical, {fixes[2] or 0} known-exploited)",
             f"• safety: {snap}", f"• reboot: {reboot}"]
    if inst:
        lines.append("• " + ", ".join(f"{n} {o or ''}→{v}".replace(" →", "→") for n, o, v in inst[:20]) +
                     (f" … +{len(inst) - 20} more" if len(inst) > 20 else ""))
    if remv:
        lines.append("• ⚠️ removals: " + ", ".join(remv[:15]))
    if bad:
        lines.append(f"🛑 REFUSED: the plan removes {', '.join(bad)} — patch this one by hand.")
    if not inst and not remv:
        lines.append("Nothing to do — already up to date.")
    timing, why, run_after = None, None, None
    if inst or remv:
        timing, why = decide_timing(t, inst, remv, fixes)
        run_after = iso() if timing == "now" else iso(next_night())
        lines.append(f"⏱ timing: **{'as soon as approved' if timing == 'now' else 'tonight ' + run_after[11:16] + ' UTC'}**"
                     f" ({why})")
    msg = "\n".join(lines)[:1900]
    if bad or (not inst and not remv):
        notify.send(msg)
        con.execute("update patch_jobs set status=?, plan=?, n_pkgs=?, n_remove=?, finished=? where id=?",
                    ("refused" if bad else "nothing", msg, len(inst), len(remv), iso(), job["id"]))
    else:
        mid = notify.post(msg + f"\n✅ = approve with that timing · {NOW_REACT} = approve and run NOW · ❌ = cancel "
                                f"(expires in {EXPIRE_H} h)")
        notify.react(mid, notify.APPROVE); notify.react(mid, NOW_REACT)
        notify.react(mid, notify.REJECT)
        con.execute("update patch_jobs set status='pending', plan=?, n_pkgs=?, n_remove=?, message_id=?, timing=?, "
                    "run_after=?, timing_why=? where id=?",
                    (msg, len(inst), len(remv), mid, timing, run_after, why, job["id"]))
    con.commit()


# ── 2. approval → run ────────────────────────────────────────────────────────
def node_of(t):
    return t["node"]


def execute(con, job):
    t = target_info(con, job["target"])
    if t["kind"] == "container":
        return execute_container(con, job, t)
    mid = job["message_id"]
    con.execute("update patch_jobs set status='running', decided=? where id=?", (iso(), job["id"])); con.commit()
    notify.post("▶️ approved — starting.", reply_to=mid)
    snap = None
    if t["kind"] == "ct":
        snap = "warden-prepatch-" + now().strftime("%Y%m%d%H%M")
        p = node_ssh(t, f"pct snapshot {t['vmid']} {snap} --description "
                        f"{sh_quote('warden patch job ' + str(job['id']))}", timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f"snapshot failed, NOT patching: {(p.stderr or p.stdout).strip()[-200:]}")
        con.execute("update patch_jobs set snapshot=? where id=?", (snap, job["id"])); con.commit()
    rc, out = remote(t, f"apt-get update -qq && {APT_ENV} apt-get -y {APT_OPTS} full-upgrade && "
                        f"{APT_ENV} apt-get -y autoremove --purge >/dev/null 2>&1; rc=$?; "
                        f"[ -f /var/run/reboot-required ] && echo __REBOOT_REQUIRED__; exit $rc", timeout=5400)
    tail = "\n".join(out.strip().splitlines()[-6:])[-600:]
    if rc != 0:
        rb = f"\nRollback: `pct rollback {t['vmid']} {snap}` on {node_of(t)}" if snap else ""
        raise RuntimeError(f"apt failed (rc {rc}):\n```{tail}```{rb}")
    need = "__REBOOT_REQUIRED__" in out
    if t["kind"] == "node":
        k = (hosts.remote(t, "uname -r; ls -1 /boot/vmlinuz-* | sed 's#.*/vmlinuz-##' | sort -V | tail -1",
                          timeout=60)[1] or "").split()
        need = need or (len(k) == 2 and k[0] != k[1])
    reboot = "not needed"
    if need and t["kind"] == "node":
        reboot = "⚠️ NEEDED — not done automatically (Proxmox node). Reboot it in a quiet window."
    elif need and t["kind"] == "ct" and is_self(t):
        reboot = "scheduled in 30 s (warden's own container reboots via its node — back in ~1-2 min)"
    elif need and (is_self(t) or t["kind"] == "local"):
        reboot = "⚠️ NEEDED — not done automatically (this is the box warden runs on). Reboot it in a quiet window."
    elif need and t["kind"] == "ct":
        p = node_ssh(t, f"pct reboot {t['vmid']} --timeout 120", timeout=300)
        reboot = "done" if p.returncode == 0 else f"FAILED: {(p.stderr or p.stdout).strip()[-120:]}"
        time.sleep(20)
    elif need and t["kind"] == "host":
        remote(t, "nohup sh -c 'sleep 5; systemctl reboot' >/dev/null 2>&1 &", timeout=60)
        reboot = f"issued ({t['name']} back in ~2 min)"
    after = None
    if not (need and t["kind"] == "ct" and is_self(t)) and not (need and t["kind"] == "host"):
        subprocess.run([sys.executable, os.path.join(HERE, "vulnscan.py"), t["target"]], capture_output=True,
                       timeout=1800)
        r = con.execute("select n_fixable from vuln_targets where target=?", (t["target"],)).fetchone()
        after = r[0] if r else None
    result = (f"✅ **{t['name']} patched** — {job['n_pkgs']} package(s). Fixable CVEs: {job['before_fix']} → "
              f"{after if after is not None else 'rescan after reboot'}. Reboot: {reboot}."
              + (f"\nRollback if anything misbehaves: `pct rollback {t['vmid']} {snap}` on {node_of(t)} "
                 f"(snapshot kept {SNAP_KEEP_DAYS} days)" if snap else ""))
    con.execute("update patch_jobs set status='done', result=?, after_fix=?, reboot=?, finished=? where id=?",
                (result, after, reboot, iso(), job["id"])); con.commit()
    notify.post(result, reply_to=mid)
    log(result.replace("\n", " "))
    if need and t["kind"] == "ct" and is_self(t):
        node_ssh(t, f"nohup sh -c 'sleep 30; pct reboot {t['vmid']}' >/dev/null 2>&1 &", timeout=60)


def prune_snapshots():
    cutoff = (now() - timedelta(days=SNAP_KEEP_DAYS)).strftime("%Y%m%d%H%M")
    for h in hosts.declared():
        if h.get("kind") != "proxmox" or not h.get("ssh"):
            continue
        rc, so, _ = hosts.run(SSH + [h["ssh"], "for c in $(pct list | awk 'NR>1{print $1}'); do "
                                     "pct listsnapshot $c 2>/dev/null | grep -o 'warden-prepatch-[0-9]*' | sed \"s/^/$c /\"; done"],
                              timeout=120)
        for line in (so or "").splitlines():
            vmid, snap = line.split()
            if snap.rsplit("-", 1)[-1] < cutoff:
                hosts.run(SSH + [h["ssh"], f"pct delsnapshot {vmid} {snap}"], timeout=600)
                log(f"pruned snapshot {vmid} {snap}")


def run_cycle():
    con = db()
    intake(con)
    for job in con.execute("select * from patch_jobs where status='planning'").fetchall():
        try:
            make_plan(con, job)
        except Exception as e:  # noqa: BLE001
            con.execute("update patch_jobs set status='failed', result=?, finished=? where id=?",
                        (f"plan: {e}"[:400], iso(), job["id"])); con.commit()
            notify.send(f"🛑 Patch plan for `{job['target']}` failed: {str(e)[:300]}")
    for job in con.execute("select * from patch_jobs where status='pending'").fetchall():
        owner = notify.owner()
        yes = notify.reactors(job["message_id"], notify.APPROVE)
        if yes is None:
            con.execute("update patch_jobs set status='expired', finished=? where id=?", (iso(), job["id"])); continue
        no = notify.reactors(job["message_id"], notify.REJECT) or []
        if owner in no:
            con.execute("update patch_jobs set status='cancelled', decided=?, finished=? where id=?",
                        (iso(), iso(), job["id"]))
            notify.post("❌ cancelled — nothing changed.", reply_to=job["message_id"])
        elif owner in (notify.reactors(job["message_id"], NOW_REACT) or []):
            con.execute("update patch_jobs set status='approved', run_after=?, timing='now (owner ⚡)' where id=?",
                        (iso(), job["id"]))
        elif owner in yes:
            con.execute("update patch_jobs set status='approved', run_after=coalesce(run_after, ?) where id=?",
                        (iso(), job["id"]))
            if (job["timing"] or "") == "tonight":
                notify.post(f"🌙 approved — scheduled for {job['run_after'][11:16]} UTC tonight ({job['timing_why']}). "
                            f"React {NOW_REACT} on the plan to run it now instead.", reply_to=job["message_id"])
        elif job["requested"] < iso(now() - timedelta(hours=EXPIRE_H)):
            con.execute("update patch_jobs set status='expired', finished=? where id=?", (iso(), job["id"]))
            notify.post("⌛ expired unanswered — nothing changed.", reply_to=job["message_id"])
        con.commit()
    for j in con.execute("select * from patch_jobs where status='approved' and run_after > ?", (iso(),)).fetchall():
        if notify.owner() in (notify.reactors(j["message_id"], NOW_REACT) or []):
            con.execute("update patch_jobs set run_after=?, timing='now (owner ⚡)' where id=?", (iso(), j["id"]))
    con.commit()
    job = con.execute("select * from patch_jobs where status='approved' and coalesce(run_after,'') <= ? "
                      "order by run_after, id limit 1", (iso(),)).fetchone()
    if job:                                   # one at a time; the next waits for the next cycle
        try:
            execute(con, job)
        except Exception as e:  # noqa: BLE001
            con.execute("update patch_jobs set status='failed', result=?, finished=? where id=?",
                        (str(e)[:900], iso(), job["id"])); con.commit()
            notify.post(f"🛑 **Patch FAILED** on `{job['target']}`: {str(e)[:1500]}", reply_to=job["message_id"])
            log(f"job {job['id']} failed: {e}")
    if now().minute < 3:                      # hourly-ish housekeeping
        prune_snapshots()
    return 0


def auto_request(dry=False):
    """The daily patch round (owner 2026-10-07: "Daily, skip if a plan is open"). Files a REQUEST for every
    patchable box with fixable CVEs or pending upgrades — the owner still ✅s each plan. Skips a box with an
    open job, or one filed in the last 20 h (so a ❌/expired plan is not re-filed the same day)."""
    con = db()
    QUEUE.mkdir(parents=True, exist_ok=True)
    queued = []
    for t in con.execute("select target, name, n_fixable, upgradable from vuln_targets where patchable=1 and "
                         "status='ok' and (n_fixable>0 or upgradable>0) order by target").fetchall():
        busy = con.execute("select 1 from patch_jobs where target=? and (status in "
                           "('planning','pending','approved','running') or requested > datetime('now','-20 hours'))",
                           (t["target"],)).fetchone()
        if busy or any(json.loads(f.read_text()).get("target") == t["target"] for f in QUEUE.glob("*.json")):
            continue
        if not dry:
            (QUEUE / f"{int(time.time() * 1000)}-auto-{t['target'].replace(':', '_')}.json").write_text(
                json.dumps({"target": t["target"], "by": "daily patch round"}))
        queued.append(f"{t['target']} (fixable {t['n_fixable']}, upgradable {t['upgradable']})")
    log(("DRY " if dry else "") + f"auto-request: {len(queued)} queued — " + ", ".join(queued))
    print("\n".join(queued) or "nothing to queue")
    return 0


def main():
    a = sys.argv[1:]
    if a and a[0] == "list":
        for r in db().execute("select id,target,status,requested,n_pkgs,before_fix,after_fix,reboot from patch_jobs "
                              "order by id desc limit 30"):
            print(" | ".join("" if x is None else str(x) for x in r))
        return 0
    if a and a[0] == "auto":
        return auto_request("--dry-run" in a)
    if a and a[0] == "request" and len(a) > 1:          # CLI path, same queue as the button
        QUEUE.mkdir(parents=True, exist_ok=True)
        (QUEUE / f"{int(time.time())}-cli.json").write_text(json.dumps({"target": a[1], "by": "cli"}))
        print("queued"); return 0
    with open(LOCK, "w") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0                                     # a long patch is still running — skip this tick
        return run_cycle()


if __name__ == "__main__":
    sys.exit(main())
