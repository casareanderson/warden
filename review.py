#!/usr/bin/env python3
"""review.py — mentor's code review, wired into warden (built 2026-10-22).

github.py records every pull request on the watched repos; this collector runs mentor over the ones that opened or got
new commits, fact-checks the findings against the diff, stores the verdict, and reports it — to Discord, and (if
enabled) back onto the GitHub PR as a review. It never edits, commits, pushes, merges or approves: the GitHub review
uses APPROVE / COMMENT / REQUEST_CHANGES as the verdict says, but mentor itself only advises; a human still merges.

  review.py            review new PRs once (timer: every 10 min, just after warden-github)
  review.py --list     the latest reviews

Config:
  review:            {url, model, key_secret}        — the model (falls back to vuln.brief)
  review.post_to_github: true                        — also POST the review onto the PR
  review.write_token_secret: GITHUB_REVIEW_TOKEN     — fine-grained token with pull_request:write (or classic repo)
  github.token_secret: GITHUB_TOKEN                  — read-only, to fetch the diff/title/body
"""
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wlib import config, notify, secrets  # noqa: E402
from wlib import review as engine  # noqa: E402

DB = config.DB
ACTIONS = ("opened", "synchronize", "reopened")


def db():
    con = sqlite3.connect(DB, timeout=60)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists runs(
        id integer primary key, ts text, source text, lines integer, parsed integer, note text);
      create table if not exists reviews(
        repo text, number integer, event_id text, ts text, verdict text, summary text,
        findings text, model text, dropped integer, gh_review text, message_id text, primary key(repo, number));
    """)
    for col in ("dropped integer", "gh_review text"):
        if col.split()[0] not in {r[1] for r in con.execute("pragma table_info(reviews)")}:
            con.execute(f"alter table reviews add column {col}")
    return con


def _http():
    import requests  # noqa: PLC0415
    return requests


def _pr(repo, number, tok):
    requests = _http()
    hdr = {"Accept": "application/vnd.github+json", "User-Agent": "warden"}
    if tok:
        hdr["Authorization"] = "Bearer " + tok
    r = requests.get(f"https://api.github.com/repos/{repo}/pulls/{number}", headers=hdr, timeout=30)
    r.raise_for_status()
    j = r.json()
    return j.get("title", ""), j.get("body", "") or "", j.get("html_url", "")


def _diff(repo, number, tok):
    requests = _http()
    hdr = {"Accept": "application/vnd.github.diff", "User-Agent": "warden"}
    if tok:
        hdr["Authorization"] = "Bearer " + tok
    r = requests.get(f"https://api.github.com/repos/{repo}/pulls/{number}", headers=hdr, timeout=30)
    r.raise_for_status()
    return r.text


def _post_review(repo, number, tok, body, event):
    requests = _http()
    r = requests.post(f"https://api.github.com/repos/{repo}/pulls/{number}/reviews",
                      headers={"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json",
                               "User-Agent": "warden"},
                      json={"body": body[:20000], "event": event}, timeout=30)
    if not r.ok:
        return False, f"HTTP {r.status_code}: {r.text[:120]}"
    j = r.json()
    return True, j.get("html_url", "")


def _line(d, dropped):
    sev = {"high": "🔴", "med": "🟠", "low": "🟡"}
    top = "\n".join(f"{sev.get(f.get('severity'), '•')} `{f.get('file') or '?'}"
                    + (f":{f['line']}" if f.get("line") else "") + f" — {f.get('title', '')}"
                    for f in (d.get("findings") or [])[:5])
    head = f"🧑‍🏫 **mentor · {d['repo'].split('/')[-1]}#{d['number']}** — `{d['verdict']}`" + \
        (f"\n{d['summary']}" if d.get("summary") else "") + ("\n" + top if top else "") + \
        (f"\n_(dropped {dropped} unverifiable finding(s))_" if dropped else "")
    return head[:1900]


def poll():
    con = db()
    if not config.get("github.owner"):
        print("review: github.owner not set — skipped"); return 0
    if not (config.get("review") or config.get("vuln.brief")):
        print("review: no AI endpoint configured (review: or vuln.brief:) — skipped"); return 0
    tok = secrets.get(config.get("github.token_secret") or "GITHUB_TOKEN")
    if not tok:
        con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'review',0,0,"
                    "'no GITHUB_TOKEN — skipped')"); con.commit()
        print("review: no GITHUB_TOKEN — skipped"); return 0
    post = bool(config.get("review.post_to_github"))
    wtok = secrets.get(config.get("review.write_token_secret") or "GITHUB_REVIEW_TOKEN") if post else ""
    newest = {}                                   # (repo, number) → newest event id
    for r in con.execute("select * from gh_events where kind='pull_request' order by id desc limit 500").fetchall():
        try:
            d = json.loads(r["detail"] or "{}")
        except ValueError:
            continue
        if d.get("action") not in ACTIONS:
            continue
        key = (r["repo"], d["number"])
        newest.setdefault(key, r["id"])
    done = 0
    for (repo, number), event_id in newest.items():
        prev = con.execute("select event_id from reviews where repo=? and number=?", (repo, number)).fetchone()
        if prev and prev["event_id"] == event_id:
            continue                                     # already reviewed this revision
        try:
            title, body, _ = _pr(repo, number, tok)
            diff = _diff(repo, number, tok)
            res = engine.review(diff, title=title, body=body)
            findings, dropped = engine.check(diff, res.get("findings", []))
            res["findings"] = findings
        except Exception as e:  # noqa: BLE001
            con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'review',0,0,?)",
                        (f"{repo}#{number}: {e}"[:200],))
            con.commit(); continue
        gh = ""
        if post and wtok:
            event = engine.VERDICT_EVENT.get(res.get("verdict"), "COMMENT")
            ok, gh = _post_review(repo, number, wtok, engine.render_body(res.get("verdict"), res.get("summary", ""), findings), event)
            if not ok:
                gh = ""
        con.execute("insert into reviews(repo,number,event_id,ts,verdict,summary,findings,model,dropped,gh_review) "
                    "values(?,?,?,datetime('now'),?,?,?,?,?,?) on conflict(repo,number) do update set "
                    "event_id=excluded.event_id, ts=excluded.ts, verdict=excluded.verdict, summary=excluded.summary, "
                    "findings=excluded.findings, model=excluded.model, dropped=excluded.dropped, gh_review=excluded.gh_review",
                    (repo, number, event_id, res.get("verdict"), res.get("summary", "")[:500],
                     json.dumps(findings), res.get("model"), dropped, gh))
        con.commit()                                     # commit BEFORE any notify call
        res["repo"], res["number"] = repo, number
        if config.get("github.notify", True):
            notify.send(_line(res, dropped), channel_id=config.get("github.channel") or None)
        done += 1
    con.execute("insert into runs(ts,source,lines,parsed,note) values(datetime('now'),'review',?,?,?)",
                (len(newest), done, f"{done} PR(s) reviewed" if done else "up to date"))
    con.commit()
    print(f"review: {done} PR(s) reviewed")
    return 0


def main():
    if "--list" in sys.argv:
        for r in db().execute("select ts,repo,number,verdict,dropped,gh_review from reviews order by ts desc limit 30"):
            print(" | ".join("" if x is None else str(x) for x in r))
        return 0
    return poll()


if __name__ == "__main__":
    sys.exit(main())
