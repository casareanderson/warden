"""Offline tests for patcher.py's auto-apply rule (patch.auto_after_days).

No network, no SSH, no real patch: a temp DB with a pending job, the reactor
lookups stubbed to "no one reacted", and the auto-apply branch observed."""
import importlib
import sys
from datetime import datetime, timedelta, timezone
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


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _seed(con, target, requested, urgent):
    con.execute("insert into patch_jobs(target,name,status,requested,message_id,urgent) values(?,?,?,?,?,?)",
                (target, target, "pending", requested, "local-1", urgent))
    con.commit()


def _stub_notify(monkeypatch, answers):
    import wlib.notify
    monkeypatch.setattr(wlib.notify, "owner", lambda: "owner1")
    monkeypatch.setattr(wlib.notify, "reactors", lambda mid, emoji: answers.get(emoji, []))
    resolved = []
    monkeypatch.setattr(wlib.notify, "resolve", lambda mid, text: resolved.append(text) or True)
    monkeypatch.setattr(wlib.notify, "post", lambda text, reply_to=None, channel=None: "local-1")
    monkeypatch.setattr(wlib.notify, "react", lambda *a, **k: None)
    return resolved


def test_nonurgent_auto_applies_after_grace(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    import wlib.config
    importlib.reload(wlib.config)
    p = load("patcher")
    monkeypatch.setattr(p, "AUTO_AFTER_DAYS", 5)
    old = datetime.now(timezone.utc) - timedelta(days=6)
    con = p.db()
    _seed(con, "ct:1", _iso(old), 0)
    resolved = _stub_notify(monkeypatch, {})
    p.run_cycle()
    row = con.execute("select status, timing, run_after from patch_jobs where target='ct:1'").fetchone()
    assert row["status"] == "approved"
    assert row["timing"].startswith("auto (") and "5 days" in row["timing"]
    assert row["run_after"] > _iso(datetime.now(timezone.utc))          # scheduled in the future (night window)
    assert any("auto-approved" in m for m in resolved)


def test_urgent_is_not_auto_applied(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    import wlib.config
    importlib.reload(wlib.config)
    p = load("patcher")
    monkeypatch.setattr(p, "AUTO_AFTER_DAYS", 5)
    old = datetime.now(timezone.utc) - timedelta(days=6)
    con = p.db()
    _seed(con, "ct:2", _iso(old), 1)          # urgent
    _stub_notify(monkeypatch, {})
    p.run_cycle()
    row = con.execute("select status from patch_jobs where target='ct:2'").fetchone()
    assert row["status"] == "pending"          # still waiting for the owner's decision, never auto-applied


def test_auto_off_keeps_old_expiry(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    import wlib.config
    importlib.reload(wlib.config)
    p = load("patcher")
    monkeypatch.setattr(p, "AUTO_AFTER_DAYS", 0)
    old = datetime.now(timezone.utc) - timedelta(hours=25)
    con = p.db()
    _seed(con, "ct:3", _iso(old), 0)
    _stub_notify(monkeypatch, {})
    p.run_cycle()
    assert con.execute("select status from patch_jobs where target='ct:3'").fetchone()["status"] == "expired"
