"""Offline tests for review.py (mentor's collector): PR fetch, diff fetch, review POST, Discord line (no network)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import review as R  # noqa: E402


def test_line_rendering():
    d = {"repo": "acme/warden", "number": 7, "verdict": "changes", "summary": "fix the injection",
         "findings": [{"severity": "high", "file": "x.py", "line": 4, "title": "SQLi"}]}
    s = R._line(d, 0)
    assert "warden#7" in s and "changes" in s and "x.py:4" in s and "SQLi" in s


def test_line_rendering_notes_dropped():
    s = R._line({"repo": "acme/w", "number": 1, "verdict": "comment", "summary": "", "findings": []}, 3)
    assert "dropped 3" in s


def _fake_requests(monkeypatch, get_fn=None, post_fn=None):
    class Fake:
        def __init__(self):
            self.get = get_fn or (lambda *a, **k: None)
            self.post = post_fn or (lambda *a, **k: None)
    f = Fake()
    monkeypatch.setattr(R, "_http", lambda: f)
    return f


def test_pr_fetches_title_and_body(monkeypatch):
    class Resp:
        def raise_for_status(self):
            pass
        def json(self):
            return {"title": "Add X", "body": "does the thing", "html_url": "https://github.com/acme/warden/pull/1"}
    _fake_requests(monkeypatch, get_fn=lambda url, **k: Resp())
    title, body, url = R._pr("acme/warden", 1, "tok")
    assert title == "Add X" and body == "does the thing" and url.endswith("/pull/1")


def test_diff_uses_diff_accept_header(monkeypatch):
    captured = {}
    class Resp:
        def raise_for_status(self):
            pass
        text = "diff --git a/x b/x"
    def get(url, **k):
        captured.update(k)
        return Resp()
    _fake_requests(monkeypatch, get_fn=get)
    out = R._diff("acme/warden", 1, "tok")
    assert out == Resp.text
    assert captured["headers"]["Accept"] == "application/vnd.github.diff"


def test_post_review_maps_event_and_url(monkeypatch):
    captured = {}
    class Resp:
        ok = True
        def json(self):
            return {"html_url": "https://github.com/acme/warden/pull/1#pullrequestreview-9"}
    _fake_requests(monkeypatch, post_fn=lambda url, **k: (captured.update({"url": url, "kw": k}) or Resp()))
    ok, url = R._post_review("acme/warden", 1, "tok", "body text", "REQUEST_CHANGES")
    assert ok and "pullrequestreview" in url
    assert captured["url"].endswith("/pulls/1/reviews")
    assert captured["kw"]["json"]["event"] == "REQUEST_CHANGES"
    assert captured["kw"]["json"]["body"] == "body text"


def test_post_review_reports_failure(monkeypatch):
    class Resp:
        ok = False
        status_code = 403
        text = "forbidden"
    _fake_requests(monkeypatch, post_fn=lambda url, **k: Resp())
    ok, err = R._post_review("acme/warden", 1, "tok", "b", "COMMENT")
    assert not ok and "403" in err
