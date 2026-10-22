#!/usr/bin/env python3
"""github.py — track GitHub pushes, commits, pull requests and reviews in warden (built 2026-10-22). No LLM.

The estate had no code-review record of its own: `oss-watch` posts new issues/PRs/stars/forks on the warden family to
Discord, but nothing kept pushes, commits or PR *reviews*, and nothing stored them in warden. This fills that gap.

Every run polls the GitHub events API for each repo in `github.repos` (default: warden, sieve, ephor — the "warden
family"), stores each new event, and posts a short line to Discord for anything new:

    push          → branch/ref, head SHA, how many commits, pusher
    commit        → each commit in the push (author + first line of the message)
    pull_request  → opened/closed/merged/edited
    review        → approved / changes requested / commented

Dedup is by GitHub's global event id (the table primary key), so a re-run or a dropped run can't double-count. Only the
first page (100 events) per repo is read — the timer is short, and `insert or ignore` makes overlaps harmless.

  github.py            poll once (timer: every 10 min)
  github.py --last 30  print the most recent tracked events

warden.yml:
    github:
      token_secret: GITHUB_TOKEN      # a classic PAT, or a fine-grained token with Contents+PRs:Read on the repos
      owner: casareanderson
      repos: [warden, sieve, ephor]   # tracked repos (owner/name)
      notify: true                    # post new activity to Discord
      channel: ""                     # optional: a different channel id for GitHub activity ("" = the alert channel)

Rules:
  - Read-only. Nothing here can create, push, merge or approve — it only records and reports.
  - A missing token is a silent skip (logged in the runs table), never a crash: a public-API blip must not stop a scan.
"""
import json
import os
import re
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, notify, secrets  # noqa: E402

DB = config.DB
API = "https://api.github.com"
DEFAULT_REPOS = ["warden", "sieve", "ephor"]

# a single commit line, one message each — not an entry per event with a wall of commits
KEEP_COMMIT = ("push",)
# event types we record (others on the feed — stars, issues, forks — are oss-watch's job)
KINDS = ("PushEvent", "PullRequestEvent", "PullRequestReviewEvent")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer, parsed integer, note text);
      create table if not exists gh_events(
        id text primary key, repo text, kind text, actor text, ts text, ref text, head text,
        n_commits integer, title text, url text, detail text);
      create index if not exists gh_events_ts on gh_events(ts);
      create table if not exists gh_commits(
        repo text, sha text, author text, message text, ts text, url text, primary key(repo, sha));
    """)
    return con


def _http():
    import requests  # noqa: PLC0415 - only needed here
    return requests


def fetch_events(repo, tok):
    """Newest-first page of events for one repo. Returns [] on any failure (an API blip is not a finding)."""
    requests = _http()
    url = f"{API}/repos/{repo}/events?per_page=100"
    hdr = {"Accept": "application/vnd.github+json", "User-Agent": "warden"}
    if tok:
        hdr["Authorization"] = f"Bearer {tok}"
    try:
        r = requests.get(url, headers=hdr, timeout=20)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        return r.json()
    except Exception as e:  # noqa: BLE001
        print(f"  {repo}: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def _commit_url(repo, sha):
    return f"https://github.com/{repo}/commit/{sha}"


def digest(ev):
    """One event dict → (kind, row, commits) where kind is the short internal label, or None to skip."""
    t = ev.get("type")
    repo = ev.get("repo", {}).get("name", "")
    actor = (ev.get("actor") or {}).get("login", "") or ""
    ts = ev.get("created_at") or ""
    base = {"id": ev["id"], "repo": repo, "actor": actor, "ts": ts,
            "ref": "", "head": "", "n_commits": 0, "title": "", "url": "", "detail": ""}
    if t == "PushEvent":
        p = ev.get("payload") or {}
        commits = p.get("commits") or []
        head = p.get("head") or ""
        row = dict(base, kind="push", ref=(p.get("ref") or "").replace("refs/heads/", ""),
                   head=head, n_commits=len(commits),
                   url=f"https://github.com/{repo}/compare/{head[:12]}" if head else "")
        out = [dict(row)]
        for c in commits:
            out.append({"id": None, "kind": "commit", "repo": repo, "actor": (c.get("author") or {}).get("name", "") or actor,
                        "ts": ts, "ref": row["ref"], "head": c.get("sha", ""), "n_commits": 1,
                        "title": (c.get("message") or "").splitlines()[0][:200],
                        "url": _commit_url(repo, c["sha"]) if c.get("sha") else "", "detail": ""})
        return out
    if t == "PullRequestEvent":
        pr = (ev.get("payload") or {}).get("pull_request") or {}
        action = (ev.get("payload") or {}).get("action", "")
        state = "merged" if (pr.get("merged")) else pr.get("state", "")
        return [dict(base, kind="pull_request", title=pr.get("title", ""), url=pr.get("html_url", ""),
                     detail=json.dumps({"number": pr.get("number"), "action": action, "state": state}))]
    if t == "PullRequestReviewEvent":
        p = ev.get("payload") or {}
        review = p.get("review") or {}
        pr = p.get("pull_request") or {}
        return [dict(base, kind="review", actor=review.get("user", {}).get("login", "") or actor,
                     title=pr.get("title", ""), url=pr.get("html_url", ""),
                     detail=json.dumps({"number": pr.get("number"), "state": review.get("state"),
                                        "reviewer": review.get("user", {}).get("login", "")}))]
    return []


def poll():
    con = db()
    owner = (config.get("github.owner") or "").strip()
    if not owner:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'github',0,0,"
                    "'github.owner not set — skipped')")
        con.commit()
        print("github: no github.owner configured — skipped")
        return 0
    repos = [f"{owner}/{r}" for r in (config.get("github.repos") or DEFAULT_REPOS)]
    tok = secrets.get(config.get("github.token_secret") or "GITHUB_TOKEN")
    if not tok:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'github',0,0,"
                    "'no GITHUB_TOKEN secret — skipped')")
        con.commit()
        print("github: no token (set GITHUB_TOKEN) — skipped")
        return 0
    total_new = 0
    messages = []
    for repo in repos:
        events = fetch_events(repo, tok)
        if events is None:
            con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),?,?,?,?)",
                        ("github", 0, 0, f"{repo}: fetch failed"))
            con.commit()
            continue
        new = 0
        for ev in events:
            if ev.get("type") not in KINDS:
                continue
            rows = digest(ev)
            for r in rows:
                if r["kind"] == "commit":
                    cur = con.execute("insert or ignore into gh_commits(repo,sha,author,message,ts,url) "
                                      "values(?,?,?,?,?,?)",
                                      (r["repo"], r["head"], r["actor"], r["title"], r["ts"], r["url"]))
                    if cur.rowcount:
                        new += 1
                        messages.append(_line(r))
                    continue
                cur = con.execute("insert or ignore into gh_events(id,repo,kind,actor,ts,ref,head,n_commits,title,url,detail) "
                                  "values(?,?,?,?,?,?,?,?,?,?,?)",
                                  (r["id"], r["repo"], r["kind"], r["actor"], r["ts"], r["ref"], r["head"],
                                   r["n_commits"], r["title"], r["url"], r["detail"]))
                if cur.rowcount:
                    new += 1
                    messages.append(_line(r))
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'github',?,?,?)",
                    (len(events), new, f"{repo}: {new} new" if new else f"{repo}: up to date"))
        con.commit()
        total_new += new
    con.commit()                                                   # commit BEFORE any notify call
    if messages and config.get("github.notify", True):
        text = "\n".join(messages[:20])
        if len(messages) > 20:
            text += f"\n… +{len(messages) - 20} more → warden · Search (type:gh)"
        notify.send(text, channel_id=config.get("github.channel") or None)
    print(f"github: {total_new} new event(s) across {len(repos)} repos")
    return 0


def _line(r):
    icon = {"push": "📦", "commit": "▫️", "pull_request": "🔀", "review": "👁"}.get(r["kind"], "•")
    repo = r["repo"].split("/", 1)[-1]
    head = f" · `{r['head'][:8]}`" if r.get("head") else ""
    title = f" — {r['title']}" if r.get("title") else ""
    who = f" by {r['actor']}" if r.get("actor") else ""
    return f"{icon} **{repo}** {r['kind'].replace('_', ' ')}{who}{head}{title}"


def main():
    if "--last" in sys.argv:
        n = int(sys.argv[sys.argv.index("--last") + 1])
        con = db()
        rows = con.execute("select ts,repo,kind,actor,ref,head,n_commits,title from gh_events order by ts desc limit ?",
                           (n,)).fetchall()
        for r in rows:
            print(" | ".join("" if x is None else str(x) for x in r))
        return 0
    return poll()


if __name__ == "__main__":
    sys.exit(main())
