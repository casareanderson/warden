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
