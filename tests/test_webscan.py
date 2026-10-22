"""Offline tests for webscan.py's nuclei JSONL parsing (no nuclei, no network)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import webscan  # noqa: E402


def test_parse_nuclei_jsonl():
    lines = [
        '{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Header","severity":"info"},"host":"https://x.example.com","matched-at":"https://x.example.com/"}',
        '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"high"},"host":"https://x.example.com","matched-at":"https://x.example.com/admin"}',
        "not json",
        "",
    ]
    rows = webscan.parse(lines)
    assert len(rows) == 2
    assert rows[1]["severity"] == "high" and rows[1]["template"] == "exposed-panel"
    assert rows[0]["name"] == "Missing Security Header"


def test_parse_skips_garbage_and_non_objects():
    rows = webscan.parse(["garbage", '{"template-id": "x"}', "  [1,2]  "])
    assert len(rows) == 1 and rows[0]["template"] == "x" and rows[0]["severity"] == "unknown"


def test_cmd_includes_targets_and_flags(monkeypatch):
    import wlib.config
    monkeypatch.setattr(wlib.config, "get", lambda k, d=None: d)
    cmd = webscan._cmd("/usr/bin/nuclei", ["https://a.example.com", "https://b.example.com"])
    assert cmd[0] == "/usr/bin/nuclei" and "-jsonl" in cmd and "-severity" in cmd
    assert cmd.count("-u") == 2 and "https://b.example.com" in cmd


class _Resp:
    def __init__(self, status=200, text="", ctype="text/html"):
        self.status_code, self.text = status, text
        self.headers = {"content-type": ctype}


class _Session:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kw):
        return self.routes.get(url)


def test_paths_matches_content_signature_not_spa_shell():
    s = _Session({
        "https://x/.env": _Resp(200, "DB_PASSWORD=secret\n", "text/plain"),      # real .env
        "https://x/.git/config": _Resp(200, "<html>spa shell</html>", "text/html"),  # SPA 200 → not a finding
        "https://x/.DS_Store": _Resp(200, "binary", "application/octet-stream"),     # binary, non-HTML → finding
    })
    rows = webscan._paths(s, "https://x", webscan.SENSITIVE, "file")
    templates = {r["template"] for r in rows}
    assert "builtin:file:.env" in templates
    assert "builtin:file:.git/config" not in templates
    assert "builtin:file:.DS_Store" in templates


def test_panels_need_a_marker():
    s = _Session({
        "https://x/phpmyadmin/": _Resp(200, "<title>phpMyAdmin</title>", "text/html"),
        "https://x/manager/html": _Resp(200, "<title>Not here</title>", "text/html"),
    })
    rows = webscan._paths(s, "https://x", webscan.PANELS, "panel")
    assert {r["template"] for r in rows} == {"builtin:panel:phpmyadmin"}


def test_headers_flags_missing():
    s = _Session({"https://x": _Resp(200, "", "text/html")})
    s.routes["https://x"].headers = {}          # nothing set → HSTS etc. missing
    rows = webscan._headers(s, "https://x")
    assert any(r["template"] == "builtin:headers:strict-transport-security" for r in rows)
    assert any(r["severity"] == "medium" for r in rows)
