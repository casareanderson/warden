"""Offline tests for wlib/review.py (mentor's engine): JSON extraction and the review call shape (no network)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wlib import review  # noqa: E402


def test_parse_plain_json():
    d = review._parse('{"verdict":"changes","summary":"s","findings":[{"severity":"high","file":"a.py","line":3,"title":"t","why":"w"}]}')
    assert d["verdict"] == "changes" and d["findings"][0]["severity"] == "high"


def test_parse_strips_code_fences_and_prose():
    d = review._parse('Here you go:\n```json\n{"verdict":"approve","summary":"looks fine","findings":[]}\n```')
    assert d["verdict"] == "approve" and d["findings"] == []


def test_parse_tolerates_trailing_comma():
    d = review._parse('{"verdict":"comment","summary":"s","findings":[{"severity":"low","file":"x","line":0,"title":"t","why":"w",},],}')
    assert d["verdict"] == "comment"


def test_review_calls_endpoint(monkeypatch):
    class Resp:
        def raise_for_status(self):
            pass
        def json(self):
            return {"choices": [{"message": {"content": '{"verdict":"comment","summary":"ok","findings":[]}'}}]}
    import wlib.review as R
    monkeypatch.setattr(R, "_cfg", lambda: ("http://x/chat/completions", "m", "k"))
    monkeypatch.setattr("requests.post", lambda url, **kw: Resp())
    d = R.review("+ x = 1", title="add x")
    assert d["verdict"] == "comment" and d["model"] == "m"


DIFF = """diff --git a/warden/github.py b/warden/github.py
--- a/warden/github.py
+++ b/warden/github.py
@@ -10,6 +10,8 @@
 old
+new one
+new two
 more
diff --git a/tools/demo.py b/tools/demo.py
--- a/tools/demo.py
+++ b/tools/demo.py
@@ -1,3 +1,4 @@
 first
 second
+third
"""


def test_check_drops_hallucinated_file():
    kept, dropped = review.check(DIFF, [
        {"severity": "high", "file": "warden/github.py", "line": 11, "title": "t", "why": "w"},
        {"severity": "high", "file": "not-in-diff.py", "line": 1, "title": "t", "why": "w"},
        {"severity": "med", "file": "github.py", "line": 0, "title": "t", "why": "w"},   # partial path, no line
        {"severity": "low", "file": "", "line": 0, "title": "t", "why": "w"},            # unlocatable, kept
    ])
    assert dropped == 1
    assert [f["file"] for f in kept] == ["warden/github.py", "github.py", ""]


def test_check_clears_out_of_range_line():
    kept, dropped = review.check(DIFF, [
        {"severity": "high", "file": "github.py", "line": 11, "title": "t", "why": "w"},   # in @@ 10..17
        {"severity": "med", "file": "github.py", "line": 999, "title": "t", "why": "w"},   # out of range
    ])
    assert kept[0]["line"] == 11
    assert kept[1]["line"] == 0 and kept[1].get("line_unverified") is True


def test_verdict_event_mapping():
    assert review.VERDICT_EVENT == {"approve": "APPROVE", "comment": "COMMENT", "changes": "REQUEST_CHANGES"}


def test_render_body():
    b = review.render_body("changes", "fix the injection", [
        {"severity": "high", "file": "x.py", "line": 4, "title": "SQLi", "why": "unsanitised"},
    ])
    assert "changes" not in b and "**`x.py:4`** — SQLi" in b and "fix the injection" in b
