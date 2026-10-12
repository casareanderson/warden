"""wlib.views.search: field terms, free text, and the new negation (-kind:x) and date: filters. Offline — a tiny
events table stands in for the estate's data; every other source table is simply absent (search tolerates that)."""
import importlib
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def views(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\n")
    import wlib.config as c
    importlib.reload(c)
    from wlib import views as v
    importlib.reload(v)
    con = sqlite3.connect(c.DB)
    con.executescript("""
      create table events(id integer primary key, ts text, source text, ip text, kind text, detail text, score int);
      insert into events(ts,source,ip,kind,detail,score) values
        ('2026-10-11 08:00:00','authelia','203.0.113.5','auth-failure','bad login',40),
        ('2026-10-11 09:00:00','npm','198.51.100.9','sqli','union select',70),
        ('2026-10-10 09:00:00','npm','198.51.100.9','path-traversal','../etc/passwd',55);
    """)
    con.commit(); con.close()
    return v


def kinds(res):
    return sorted(r["kind"] for r in res["rows"])


def test_field_match(views):
    assert kinds(views.search("kind:sqli")) == ["sqli"]
    assert kinds(views.search("src:npm")) == ["path-traversal", "sqli"]
    assert kinds(views.search("type:log")) == ["auth-failure", "path-traversal", "sqli"]


def test_negation(views):
    assert kinds(views.search("-kind:auth-failure")) == ["path-traversal", "sqli"]
    assert kinds(views.search("src:npm -kind:sqli")) == ["path-traversal"]


def test_date_filter(views):
    assert kinds(views.search("date:2026-10-11")) == ["auth-failure", "sqli"]
    assert kinds(views.search("date:2026-10-10")) == ["path-traversal"]


def test_free_text_and_negation(views):
    assert kinds(views.search("union")) == ["sqli"]
    assert kinds(views.search("-passwd type:log")) == ["auth-failure", "sqli"]


def test_ip_prefix(views):
    assert kinds(views.search("ip:198.51.100")) == ["path-traversal", "sqli"]
