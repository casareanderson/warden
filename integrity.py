#!/usr/bin/env python3
"""integrity.py — agentless endpoint integrity for warden (built 2026-10-07). No LLM, nothing installed.

  integrity.py              light sweep (timer: hourly) — files, accounts, listeners, suspicious processes
  integrity.py --deep       + setuid binaries, kernel modules, `dpkg --verify` (timer: daily 04:10)
  integrity.py poll         owner ✅ on a drift message = accept as the new baseline; ❌ = keep open
  integrity.py --list       open findings

Each sweep runs ONE read-only POSIX sh script on the box over the access path in warden.yml `hosts:` (ssh to
Proxmox nodes, `pct exec` into containers, a user + sudo -S on plain hosts) and records `kind \t item \t value` facts.
The first sweep of a box is its BASELINE (silent). Later sweeps diff against the accepted baseline:
  changed / new / removed security-critical files, uid-0 or login-shell accounts, listening sockets,
  setuid files, kernel modules → drift findings, one summary per sweep via wlib.notify (✅/❌ there or on
  the dashboard).
Some facts need no baseline — they are bad on sight: processes running from /tmp, /dev/shm, /var/tmp or a
deleted binary, /etc/ld.so.preload with content, a uid-0 account that isn't root, and `dpkg --verify`
checksum mismatches on non-config package files.

Changes made by an approved patch job (patch_jobs, same target, finished since the last sweep) are tagged
"expected (patch #N)" in the message so they are easy to accept.
"""
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify  # noqa: E402   (one definition of "the estate")

DB = config.DB
SWEPT = ("node", "ct", "host", "local")

COLLECT = r'''
export LC_ALL=C
h() { for f in "$@"; do [ -f "$f" ] && [ ! -L "$f" ] && printf 'file\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | cut -c1-16)"; done; }
h /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config \
  /etc/ssh/sshd_config.d/* /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /etc/crontab /etc/cron.d/* \
  /var/spool/cron/crontabs/* /etc/ld.so.preload /etc/rc.local /etc/profile /etc/profile.d/* /etc/bash.bashrc \
  /root/.bashrc /root/.profile /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/sudo /etc/environment \
  /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*/*.conf \
  /usr/local/bin/* /usr/local/sbin/* /etc/hosts.allow /etc/hosts.deny
awk -F: '$3==0{print "uid0\t"$1"\tyes"} $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print "login\t"$1"\t"$7}' /etc/passwd
[ -s /etc/ld.so.preload ] && printf 'bad\tld.so.preload\t%s\n' "$(head -c 200 /etc/ld.so.preload | tr '\n' ' ')"
if command -v ss >/dev/null; then
  ss -H -tulnp 2>/dev/null | awk '{p=$7; sub(/.*\(\("/,"",p); sub(/".*/,"",p); a=$5; sub(/%[^:]*/,"",a); print "listen\t"$1" "a"\t"p}' | sort -u
fi
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in
    /tmp/*|/dev/shm/*|/var/tmp/*) printf 'bad\tproc %s\t%s %s\n' "${p#/proc/}" "$e" "$(tr '\0' ' ' < $p/cmdline 2>/dev/null | head -c 120)";;
    *" (deleted)")
      # a package upgrade replaced the file under a running process: "restart pending", not malware.
      # Only a deleted binary with NOTHING at that path any more (or outside /usr,/lib,/opt) is suspicious.
      f="${e% (deleted)}"
      case "$f" in /usr/*|/lib/*|/lib64/*|/opt/*|/snap/*) [ -e "$f" ] && { printf 'stale\t%s\trestart pending\n' "$f"; continue; };; esac
      printf 'bad\tproc %s\t%s %s\n' "${p#/proc/}" "$e" "$(tr '\0' ' ' < $p/cmdline 2>/dev/null | head -c 120)";;
  esac
done
if [ "$DEEP" = 1 ]; then
  find /usr /bin /sbin /opt /usr/local -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do printf 'suid\t%s\t%s\n' "$f" "$(sha256sum "$f" | cut -c1-16)"; done
  [ "$HOSTK" = 1 ] && [ -r /proc/modules ] && awk '{print "module\t"$1"\tloaded"}' /proc/modules 2>/dev/null | head -400
  command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | awk '$2!="c" && $1 ~ /5/ {print "bad\tdpkg-verify "$NF"\tchecksum mismatch vs package"}' | head -50
fi
true
'''

# kinds diffed against the baseline (drift) vs judged on sight (bad)
DIFFED = ("file", "uid0", "login", "listen", "suid", "module")
# listeners that legitimately churn (ephemeral client ports, DHCP) — keep noise out
# Proxmox's LXC setup rewrites these inside every container — a dpkg --verify mismatch there is expected
KNOWN_LXC_MODIFIED = ("/container-getty@.service", "/getty@.service", "/console-getty.service")
IGNORE_LISTEN_PROCS = {"dhclient", "systemd-network", "chronyd", "avahi-daemon", "systemd-resolve"}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists integ_base(target text, kind text, item text, value text,
        primary key(target, kind, item));
      create table if not exists integ_find(id integer primary key, ts text, target text, kind text, item text,
        old text, new text, change text, status text, message_id text, note text);
      create index if not exists if_status on integ_find(status);
      create table if not exists integ_runs(target text primary key, ts text, deep_ts text, facts integer,
        status text, note text);
    """)
    return con


def collect(t, deep):
    # containers see the HOST's /proc/modules — only real hosts report kernel modules
    script = f"DEEP={int(deep)}\nHOSTK={int(t['kind'] in ('node', 'host', 'local'))}\n" + COLLECT
    # plain hosts need root to read shadow/sudoers: sudo -S with the host's sudo_secret, over stdin
    rc, out, se = hosts.remote(t, script, timeout=900, root=t["kind"] in ("host", "local"))
    out = out or ""
    facts, stale = {}, set()
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3 and parts[0] == "stale":
            stale.add(parts[1]); continue
        if len(parts) == 3 and parts[0] in DIFFED + ("bad",):
            k, item, val = parts
            if k == "listen" and val in IGNORE_LISTEN_PROCS:
                continue
            if k == "listen":
                # loopback listeners on ephemeral ports (e.g. a local LLM server picks a new one per model load)
                # churn by design: key them by program, so a NEW program still shows but a new port doesn't
                proto, _, addr = item.partition(" ")
                host, _, port = addr.rpartition(":")
                if port.isdigit() and int(port) >= 32768 and host.strip("[]") in ("127.0.0.1", "::1", "127.0.0.53"):
                    item = f"{proto} loopback:ephemeral {val}"
            if k == "bad" and t["kind"] == "ct" and item.endswith(KNOWN_LXC_MODIFIED):
                continue
            # LXC/runc re-exec themselves from a memfd on purpose (CVE-2019-5736 defence) — ONLY these exact
            # names, only on the hypervisor; any other fileless (memfd) process stays 🚨.
            if k == "bad" and t["kind"] == "node" and item.startswith("proc ") and \
                    val.split(" (deleted)")[0] in ("/memfd:lxc-attach", "/memfd:runc_cloned:/proc/self/exe", "/memfd:runc"):
                continue
            facts[(k, item)] = val
    if not facts:
        raise RuntimeError("collector returned nothing")
    facts[("meta", "stale")] = str(len(stale))          # processes needing a restart after upgrades (info only)
    return facts


def sweep(deep=False, only=None):
    con = db()
    msgs = []
    for t in hosts.targets():
        if t["kind"] not in SWEPT or (only and t["target"] != only):
            continue
        try:
            facts = collect(t, deep)
        except Exception as e:  # noqa: BLE001
            con.execute("insert into integ_runs(target,ts,status,note) values(?,?,?,?) on conflict(target) do update "
                        "set ts=excluded.ts, status='error', note=excluded.note", (t["target"], now(), "error", str(e)[:200]))
            con.commit(); print(f"{t['target']}: ERROR {e}"); continue
        base = {(r["kind"], r["item"]): r["value"] for r in
                con.execute("select kind,item,value from integ_base where target=?", (t["target"],))}
        first = not base
        lines = []
        # ---- bad on sight
        for (k, item), val in facts.items():
            if k != "bad":
                continue
            open_ = con.execute("select 1 from integ_find where target=? and kind='bad' and item=? and status='open'",
                                (t["target"], item)).fetchone()
            if not open_:
                con.execute("insert into integ_find(ts,target,kind,item,new,change,status) values(?,?,?,?,?,?,?)",
                            (now(), t["target"], "bad", item, val, "suspicious", "open"))
                lines.append(f"🚨 {item}: {val}")
        if first:
            con.executemany("insert or replace into integ_base values(?,?,?,?)",
                            [(t["target"], k, i, v) for (k, i), v in facts.items() if k in DIFFED])
            print(f"{t['target']}: baseline {len(facts)} facts")
        else:
            kinds_now = {k for k, _ in facts}
            for key in set(base) | {k for k in facts if k[0] in DIFFED}:
                k, item = key
                if k in ("suid", "module") and not deep:
                    continue                                    # only the deep sweep collects these
                old, new = base.get(key), facts.get(key)
                if old == new or (new is None and k not in kinds_now and k in ("suid", "module")):
                    continue
                change = "new" if old is None else "removed" if new is None else "changed"
                dup = con.execute("select 1 from integ_find where target=? and kind=? and item=? and status='open' "
                                  "and coalesce(new,'')=coalesce(?, '')", (t["target"], k, item, new)).fetchone()
                if dup:
                    continue
                con.execute("insert into integ_find(ts,target,kind,item,old,new,change,status) values(?,?,?,?,?,?,?,?)",
                            (now(), t["target"], k, item, old, new, change, "open"))
                lines.append(f"{'➕' if change == 'new' else '➖' if change == 'removed' else '✏️'} {k} {item}"
                             + (f" → {new}" if k in ("listen", "login") and new else ""))
        stale_n = facts.pop(("meta", "stale"), "0")
        con.execute("insert into integ_runs(target,ts,deep_ts,facts,status,note) values(?,?,?,?,?,?) on conflict(target) "
                    "do update set ts=excluded.ts, deep_ts=coalesce(excluded.deep_ts, integ_runs.deep_ts), "
                    "facts=excluded.facts, status='ok', note=excluded.note",
                    (t["target"], now(), now() if deep else None, len(facts), "ok",
                     ("baseline · " if first else "") + (f"{stale_n} process(es) need a restart after upgrades"
                                                         if stale_n != "0" else "")))
        con.commit()
        if lines:
            patch = con.execute("select id from patch_jobs where target=? and status='done' and finished > "
                                "datetime('now','-1 day') order by id desc limit 1", (t["target"],)).fetchone() \
                if con.execute("select name from sqlite_master where name='patch_jobs'").fetchone() else None
            msgs.append((t, lines, patch))
    for t, lines, patch in msgs:
        if patch:
            # warden's own patch run changed these files/listeners: accept them into the baseline quietly.
            # Only 🚨 (bad) and login/uid0 changes still need a human after a patch.
            n = con.execute("select count(*) from integ_find where target=? and status='open' and message_id is null "
                            "and kind in ('file','suid','module','listen')", (t["target"],)).fetchone()[0]
            for r in con.execute("select * from integ_find where target=? and status='open' and message_id is null "
                                 "and kind in ('file','suid','module','listen')", (t["target"],)).fetchall():
                if r["change"] == "removed":
                    con.execute("delete from integ_base where target=? and kind=? and item=?", (r["target"], r["kind"], r["item"]))
                else:
                    con.execute("insert or replace into integ_base values(?,?,?,?)", (r["target"], r["kind"], r["item"], r["new"]))
                con.execute("update integ_find set status='accepted', note=? where id=?",
                            (f"auto: changed by warden patch #{patch[0]}", r["id"]))
            con.commit()
            lines = [l for l in lines if l.startswith("🚨") or " login " in l or " uid0 " in l]
            print(f"{t['target']}: {n} change(s) auto-accepted (patch #{patch[0]})")
            if not lines:
                continue
        head = f"🧬 **Integrity drift: {t['name']}** (`{t['target']}`)"
        body = "\n".join(lines[:8]) + (f"\n… +{len(lines) - 8} more → warden · Endpoints" if len(lines) > 8 else "")
        try:
            mid = notify.post(f"{head}\n{body}\n✅ = expected, accept as the new baseline · ❌ = keep open, I'll investigate")
            notify.react(mid, notify.APPROVE); notify.react(mid, notify.REJECT)
            con.execute("update integ_find set message_id=? where target=? and status='open' and message_id is null",
                        (mid, t["target"]))
            con.commit()
        except Exception as e:  # noqa: BLE001
            print(f"notify: {e}")
        print(head + "\n" + body)
    return 0


def poll():
    con = db()
    owner = notify.owner()
    for (mid,) in con.execute("select distinct message_id from integ_find where status='open' and message_id is not null"
                              ).fetchall():
        yes = notify.reactors(mid, notify.APPROVE)
        if yes is None:
            continue
        no = notify.reactors(mid, notify.REJECT) or []
        if owner in yes and owner not in no:
            rows = con.execute("select * from integ_find where message_id=? and status='open'", (mid,)).fetchall()
            for r in rows:
                if r["kind"] == "bad":
                    con.execute("update integ_find set status='accepted', note='owner ✅' where id=?", (r["id"],))
                    continue
                if r["change"] == "removed":
                    con.execute("delete from integ_base where target=? and kind=? and item=?", (r["target"], r["kind"], r["item"]))
                else:
                    con.execute("insert or replace into integ_base values(?,?,?,?)", (r["target"], r["kind"], r["item"], r["new"]))
                con.execute("update integ_find set status='accepted', note='owner ✅ — new baseline' where id=?", (r["id"],))
            con.commit()
            notify.resolve(mid, f"✅ accepted — {len(rows)} change(s) are the new baseline")
        elif owner in no:
            con.execute("update integ_find set note='owner ❌ — investigating' where message_id=? and status='open'", (mid,))
            con.commit()
    return 0


def main():
    a = sys.argv[1:]
    if a and a[0] == "poll":
        return poll()
    if a and a[0] == "--list":
        for r in db().execute("select id,ts,target,kind,change,item,new,status from integ_find where status='open' order by id"):
            print(" | ".join("" if x is None else str(x) for x in r))
        return 0
    only = next((x for x in a if not x.startswith("--")), None)
    return sweep(deep="--deep" in a, only=only)


if __name__ == "__main__":
    sys.exit(main())
