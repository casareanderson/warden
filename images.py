#!/usr/bin/env python3
"""images.py — Docker image advisor for warden (built 2026-10-07). No LLM.

Docker images were the author's estate's real exposure on day one (one docker host: 9 KEV / 86 critical-fixable,
another: 7 / 276) while the hosts themselves were clean. A blind auto-updater is unsafe: pinned versions (e.g. a
photo server pinned to v3.0.1), local builds (`myapp:local`) and plain `docker run` containers can't just be "pulled".

  images.py          refresh the advice table (runs after vulnscan, and hourly)
  images.py --list   print it

Per running container: how it's managed (compose / docker run / local build), whether a NEWER image for the same
tag is ALREADY PULLED (container just needs re-creating — 14 of them on day one), its KEV / critical-fixable
counts from the vuln scan, and the action:
  recreate  — compose + newer image on disk: `docker compose up -d --no-deps <svc>` (patchable, owner ✅)
  pull      — compose + floating tag (latest/stable/major): pull then recreate (patchable, owner ✅)
  manual    — docker run / local build / pinned version: the exact reason is shown; nothing automatic
"""
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, hosts  # noqa: E402

DB = config.DB
FACTS = r'''docker ps --format '{{.Names}}' | while read -r c; do
  cfg=$(docker inspect -f '{{.Config.Image}}' "$c"); run=$(docker inspect -f '{{.Image}}' "$c")
  tagid=$(docker image inspect -f '{{.Id}}' "$cfg" 2>/dev/null || echo none)
  wd=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c")
  svc=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")
  created=$(docker image inspect -f '{{.Created}}' "$run" 2>/dev/null | cut -c1-10)
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$c" "$cfg" "$([ "$run" = "$tagid" ] && echo same || echo newer)" "$wd" "$svc" "$created" "$(echo "$run" | cut -c8-19)"
done'''
FLOATING = ("latest", "stable", "main", "release")
CASAOS = ("/var/lib/casaos/apps", "/DATA/.casaos/apps")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.executescript("""
      create table if not exists img_advice(host text, container text, image text, managed text, workdir text,
        service text, newer_pulled integer, image_date text, kev integer, crit_fix integer, fixable integer,
        action text, why text, ts text, primary key(host, container));
    """)
    return con


def facts(host):
    """One line per running container on the docker host whose images-target id is `host` (img:<name>)."""
    rc, so, _ = hosts.remote(hosts.docker_host(host), FACTS, timeout=120)
    return [l.split("|") for l in (so or "").splitlines() if l.count("|") == 6]


def advise(image, newer, wd, svc):
    tag = image.split("@")[0].rsplit(":", 1)[-1] if ":" in image.split("/")[-1] else "latest"
    local = "/" not in image and "." not in image.split(":")[0] and image.split(":")[0] not in (
        "redis", "python", "postgres", "nginx", "alpine")
    if not wd:
        return "run", "manual", ("plain `docker run` — re-creating needs its original flags; update by hand"
                                 + (" (a newer image is ALREADY pulled)" if newer else ""))
    managed = "casaos" if wd.startswith(CASAOS) else "compose"
    if local or image.startswith("sha256:"):
        return managed, "manual", "locally built image — rebuild from its source, then recreate"
    if "@sha256:" in image:
        return managed, "manual", "pinned by digest — bump the digest in the compose file"
    if newer:
        return managed, "recreate", f"newer `{tag}` image already on disk — `docker compose up -d {svc}` applies it"
    if tag in FLOATING or tag.isdigit() or (tag.count(".") == 0 and tag.replace("pg", "").isdigit()):
        return managed, "pull", f"floating tag `{tag}` — pull then recreate"
    return managed, "manual", f"pinned version `{tag}` — choose the next version yourself (may need migration)"


def main():
    con = db()
    if "--list" in sys.argv:
        for r in con.execute("select host,container,managed,newer_pulled,kev,crit_fix,action,why from img_advice "
                             "order by kev desc, crit_fix desc"):
            print(r)
        return 0
    for host in [t["target"] for t in hosts.targets(discover=False) if t["kind"] == "images"]:
        try:
            rows = facts(host)
        except Exception as e:  # noqa: BLE001
            print(f"{host}: {e}"); continue
        if not rows:
            continue
        con.execute("delete from img_advice where host=?", (host,))
        for c, image, newer, wd, svc, created, short in rows:
            # vulnscan records `docker ps` {{.Image}}: the tag name, or the short ID once the tag has moved on
            v = con.execute("select coalesce(sum(kev),0), coalesce(sum(severity='CRITICAL' and fixed!=''),0), "
                            "coalesce(sum(fixed!=''),0) from vulns where target=? and image in (?,?)",
                            (host, image, short)).fetchone()
            managed, action, why = advise(image, newer == "newer", wd, svc)
            con.execute("insert into img_advice values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (host, c, image, managed, wd, svc, int(newer == "newer"), created, v[0], v[1], v[2], action, why,
                         now()))
        con.commit()
        print(f"{host}: {len(rows)} containers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
