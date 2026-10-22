"""Offline tests for github.py: event digestion, dedup and the poll cycle (no network).

Points WARDEN_HOME at a temp dir, reloads config and github, and stubs out the
GitHub API + notify, so nothing touches the network or a real install."""
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(name):
    if name in sys.modules:
        return importlib.reload(sys.modules[name])
    return importlib.import_module(name)


def _home(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("WARDEN_HOME", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path / "data"))
    import wlib.config
    importlib.reload(wlib.config)
    return tmp_path


# ── pure parsing ────────────────────────────────────────────────────────────
def test_digest_push_event():
    g = load("github")
    ev = {"id": "111", "type": "PushEvent", "repo": {"name": "acme/warden"}, "created_at": "2026-10-22T10:00:00Z",
          "actor": {"login": "alice"},
          "payload": {"ref": "refs/heads/main", "head": "abc123def456",
                      "commits": [{"sha": "c1", "message": "fix a thing\nmore", "author": {"name": "alice"}},
                                  {"sha": "c2", "message": "docs", "author": {"name": "bob"}}]}}
    rows = g.digest(ev)
    push = rows[0]
    assert push["kind"] == "push" and push["ref"] == "main" and push["n_commits"] == 2 and push["head"] == "abc123def456"
    commits = [r for r in rows if r["kind"] == "commit"]
    assert len(commits) == 2
    assert commits[0]["title"] == "fix a thing"            # first line only
    assert commits[0]["url"].endswith("/commit/c1")


def test_digest_pr_and_review():
    g = load("github")
    pr = {"id": "222", "type": "PullRequestEvent", "repo": {"name": "acme/sieve"}, "created_at": "t", "actor": {"login": "a"},
          "payload": {"action": "closed", "pull_request": {"number": 7, "title": "Add X", "merged": True,
                                                           "html_url": "https://github.com/acme/sieve/pull/7", "state": "closed"}}}
    (row,) = g.digest(pr)
    assert row["kind"] == "pull_request" and json.loads(row["detail"])["state"] == "merged"
    rv = {"id": "333", "type": "PullRequestReviewEvent", "repo": {"name": "acme/ephor"}, "created_at": "t",
          "actor": {"login": "a"}, "payload": {"review": {"state": "approved", "user": {"login": "carol"}},
                                                "pull_request": {"number": 9, "title": "P", "html_url": "u"}}}
    (row,) = g.digest(rv)
    assert row["kind"] == "review" and row["actor"] == "carol" and json.loads(row["detail"])["state"] == "approved"


def test_digest_skips_irrelevant():
    g = load("github")
    assert g.digest({"id": "9", "type": "WatchEvent", "repo": {"name": "x/y"}, "created_at": "t"}) == []


# ── poll cycle: insert, dedup, notify ───────────────────────────────────────
def test_poll_inserts_dedups_and_notifies(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    (tmp_path / "warden.yml").write_text("github:\n  owner: acme\n  repos: [warden]\n")
    g = load("github")
    import wlib.config
    importlib.reload(wlib.config)

    sent = []
    monkeypatch.setattr(g, "fetch_events", lambda repo, tok: [
        {"id": "100", "type": "PushEvent", "repo": {"name": "acme/warden"}, "created_at": "2026-10-22T10:00:00Z",
         "actor": {"login": "alice"}, "payload": {"ref": "refs/heads/main", "head": "abc", "commits": []}},
        {"id": "200", "type": "PullRequestEvent", "repo": {"name": "acme/warden"}, "created_at": "2026-10-22T11:00:00Z",
         "actor": {"login": "bob"}, "payload": {"action": "opened",
                                                 "pull_request": {"number": 1, "title": "T", "html_url": "u"}}},
    ])
    import wlib.notify
    monkeypatch.setattr(wlib.notify, "send", lambda text, channel_id=None: sent.append(text))
    monkeypatch.setattr(g.secrets, "get", lambda name: "tok")

    g.poll()
    con = g.db()
    assert con.execute("select count(*) from gh_events").fetchone()[0] == 2
    assert len(sent) == 1 and "warden" in sent[0]

    sent.clear()
    g.poll()                                            # same events again → dedup, no re-notify
    assert con.execute("select count(*) from gh_events").fetchone()[0] == 2
    assert sent == []


def test_poll_requires_token_and_owner(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    g = load("github")
    import wlib.config
    importlib.reload(wlib.config)
    monkeypatch.setattr(g, "fetch_events", lambda *a: (_ for _ in ()).throw(AssertionError("no network")))
    assert g.poll() == 0          # no owner → skip before any network call
