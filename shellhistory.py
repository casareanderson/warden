#!/usr/bin/env python3
"""shellhistory.py — agentless audit of the shell commands run on each box (built 2026-10-22). No LLM.

warden's integrity sweep watches the *files* that matter but never saw what people (or agents) actually TYPE. This
collector reads the bash/zsh history of root and every login user on each watched box — one read-only POSIX sh script
over the same access path integrity.py uses — and flags the commands worth a second look:

    privilege   sudo / su / doas
    destructive rm -rf, dd, mkfs, pct destroy, docker rm/rmi/prune, truncate
    history     git push --force, git reset --hard, git clean -f   (the estate had a force-push clobber 2026-10-12)
    remote      curl|wget … | sh (pipe-to-shell)
    secret      a line that sets a secret-looking variable in history (tokens never belong in shell history)
    network     firewall down / iptables flush

Only FLAGGED commands go to Discord (and the value half of any `KEY=value` is redacted first — a secret in history
must not be re-broadcast). Every new command is stored in warden's DB, so the console/search can show what ran where.

Watermarking: bash rotates its history file (HISTSIZE) and drops the OLDEST lines, so a line-count offset would go
blind at the top while the file stays the same length. The collector instead remembers the last few commands it saw
and resumes after them; a history that was reset/cleared is re-baselined silently rather than re-flagged.

  shellhistory.py            sweep once (timer: hourly)
  shellhistory.py --list     the most recent flagged commands
"""
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts, notify  # noqa: E402

DB = config.DB
SWEPT = ("node", "ct", "host", "local")
TAIL = 3                       # commands remembered per file to resume after a rotation
MAX_LINES = 5000               # read at most this many of the newest lines per file

COLLECT = r'''
export LC_ALL=C
for f in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do
  [ -f "$f" ] || continue
  tail -n 5000 "$f" | awk -v p="$f" '{print p "\t" $0}'
done
true
'''

# (label, compiled regex) — ordered; the first match names the flag. Conservative on purpose: these are the commands
# that change something hard to undo, escalate, or leak a secret. Everything else is recorded but not flagged.
FLAGS = [
    ("secret",    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|pat)\s*=\s*\S+")),
    ("secret",    re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                             r"|sk-[A-Za-z0-9_-]{20,}|xox[bp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b")),
    ("destructive", re.compile(r"(?i)(rm\s+(-\w*\s+)*-?rf\b|rm\s+(-rf|-fr)|dd\s+if=|mkfs\.|\bmkfs\s|"
                               r"\bpct\s+(destroy|delete|stop)\b|\bdocker\s+(rm|rmi)\b|docker\s+system\s+prune|"
                               r"\btruncate\s+-s)")),
    ("history",   re.compile(r"(?i)(git\s+push\s+(--force|-f)|git\s+reset\s+--hard|git\s+clean\s+(-f|-fd|-x))")),
    ("remote",    re.compile(r"(?i)(curl|wget)\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\s*-O\s*-\s*\|\s*sh")),
    ("privilege", re.compile(r"(?i)(^|\s)(sudo|su|doas)\s")),
    ("network",   re.compile(r"(?i)(\bufw\s+disable\b|\biptables\s+(-F|--flush)\b|\biptables\s+-P\s+\w+\s+ACCEPT\b)")),
]

REDACT = re.compile(r"(?i)(\b(password|passwd|secret|api[_-]?key|token|pat|key)\s*=\s*)\S+")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer, parsed integer, note text);
      create table if not exists shell_cmds(
        id integer primary key, ts text, target text, user text, path text,
        command text, flagged integer, why text);
      create index if not exists shell_cmds_flagged on shell_cmds(flagged);
      create table if not exists shell_wm(target text, path text, tail text, primary key(target, path));
    """)
    return con


def user_of(path):
    m = re.search(r"/home/([^/]+)/", path)
    return m.group(1) if m else "root"


def flag(command):
    for label, rx in FLAGS:
        if rx.search(command):
            return label
    return ""


def redact(command):
    return REDACT.sub(r"\1•••", command)


def _parse(out):
    """Collector output lines `path<TAB>command` → ordered list of (path, command); zsh's `: ts:0;cmd` prefix stripped."""
    seen = []
    for line in (out or "").splitlines():
        if "\t" not in line:
            continue
        path, _, cmd = line.partition("\t")
        if cmd.startswith(": ") and ";":                # zsh extended-history prefix `: 1234567890:0;`
            cmd = cmd.partition(";")[2]
        if not cmd.strip():
            continue
        seen.append((path, cmd))
    return seen


def sweep(only=None):
    con = db()
    flagged_msgs, counts = [], {}
    for t in hosts.targets():
        if t["kind"] not in SWEPT or (only and t["target"] != only):
            continue
        try:
            rc, out, _ = hosts.remote(t, COLLECT, timeout=60, root=t["kind"] in ("host", "local"))
        except Exception as e:  # noqa: BLE001
            con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'shell',0,0,?)",
                        (f"{t['target']}: {e}"[:200],))
            con.commit()
            print(f"{t['target']}: ERROR {e}")
            continue
        rows = _parse(out)
        by_file = {}
        for path, cmd in rows:
            by_file.setdefault(path, []).append(cmd)
        new = 0
        for path, lines in by_file.items():
            if len(lines) > MAX_LINES:
                lines = lines[-MAX_LINES:]
            prev = con.execute("select tail from shell_wm where target=? and path=?", (t["target"], path)).fetchone()
            prev = json.loads(prev[0]) if prev and prev[0] else []
            if prev:
                idx = -1
                for i in range(len(lines) - len(prev), -1, -1):
                    if lines[i:i + len(prev)] == prev:
                        idx = i + len(prev)
                        break
                fresh = lines[idx:] if idx >= 0 else []        # not found → history was reset: re-baseline silently
            else:
                fresh = []                                     # first sweep = baseline, not a flood of old commands
            user = user_of(path)
            for cmd in fresh:
                why = flag(cmd)
                con.execute("insert into shell_cmds(ts,target,user,path,command,flagged,why) values(?,?,?,?,?,?,?)",
                            (now(), t["target"], user, path, cmd, 1 if why else 0, why))
                new += 1
                if why:
                    flagged_msgs.append(f"`{t['target']}` {user}: {redact(cmd)[:200]}")
            if lines:
                con.execute("insert into shell_wm(target,path,tail) values(?,?,?) on conflict(target,path) "
                            "do update set tail=excluded.tail",
                            (t["target"], path, json.dumps(lines[-TAIL:])))
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'shell',?,?,?)",
                    (len(rows), new, f"{t['target']}: {new} new" if new else f"{t['target']}: up to date"))
        con.commit()
        counts[t["target"]] = new
        print(f"{t['target']}: {new} new command(s)")
    if flagged_msgs:
        notify.send("🖥 **Shell history flags**\n" + "\n".join(flagged_msgs[:15])
                    + (f"\n… +{len(flagged_msgs) - 15} more → warden · Search (type:shell)" if len(flagged_msgs) > 15 else ""))
    return 0


def main():
    if "--list" in sys.argv:
        for r in db().execute("select ts,target,user,command,why from shell_cmds where flagged=1 order by id desc limit 50"):
            print(" | ".join(x or "" for x in r))
        return 0
    return sweep()


if __name__ == "__main__":
    sys.exit(main())
