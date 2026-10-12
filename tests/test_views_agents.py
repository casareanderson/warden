"""wlib.views agent-access helpers: decoding a Linux capability mask and deciding whether an agent's uid/gids
could read a file from its owner:group:mode stat. Pure functions, fully offline."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wlib import views  # noqa: E402


def test_caps_full_root():
    names, full = views._caps("000001ffffffffff")
    assert full is True
    assert "sys_admin" in names and "net_raw" in names


def test_caps_single_bit():
    names, full = views._caps("0000000000000400")   # bit 10 = cap_net_bind_service
    assert full is False and names == ["net_bind_service"]


def test_caps_net_admin():
    names, full = views._caps("%x" % (1 << 12))      # bit 12 = cap_net_admin
    assert names == ["net_admin"] and full is False


def test_caps_garbage_is_empty():
    assert views._caps("not-hex") == ([], False)
    assert views._caps(None) == ([], False)


def test_can_read_root_reads_anything():
    assert views._can_read(0, 0, "", "1000:1000:600") is True


def test_can_read_owner_bit():
    # owner 1000, mode 600 → owner can read, nobody else
    assert views._can_read(1000, 1000, "", "1000:1000:600") is True
    assert views._can_read(1001, 1001, "", "1000:1000:600") is False


def test_can_read_group_bit():
    # group 50, mode 640 → a member of group 50 can read
    assert views._can_read(1001, 50, "", "1000:50:640") is True
    assert views._can_read(1001, 99, "7 50 8", "1000:50:640") is True   # 50 among supplementary gids
    assert views._can_read(1001, 99, "7 8", "1000:50:640") is False


def test_can_read_other_bit():
    assert views._can_read(1001, 1001, "", "1000:1000:644") is True     # world-readable
    assert views._can_read(1001, 1001, "", "1000:1000:640") is False    # no other-read


def test_can_read_unknown_stat_is_none():
    assert views._can_read(1000, 1000, "", "garbage") is None


import importlib as _il
import sqlite3 as _sql


def _agents_db_without_bytes(tmp_path, monkeypatch):
    """A pre-v3.1 DB: agent_conns has no bytes_recv column; the other agent_* tables exist but are empty."""
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test, timezone: Europe/London, lan: [192.168.0.0/16]}\nnotify: {backend: none}\n")
    import wlib.config as c
    _il.reload(c)
    db = _sql.connect(str(c.DB))
    db.executescript("""
      create table agent_conns(agent,host,dest,dest_ip,port,domain,first_seen,last_seen,hits,container,sample_cmd);
      create table agent_alerts(id integer primary key, ts,agent,host,dest,dest_ip,kind,feed,detail);
      create table agent_findings(id integer primary key, ts,agent,host,dest,score,decision,reasons,explain,verdict);
      create table agent_runs(host,ts,status,note,seen,attributed);
    """)
    db.execute("insert into agent_conns values('hermes:sec','box','api.example.com','93.184.216.34',443,"
               "'api.example.com','2026-10-01','2026-10-02',5,'','hermes')")
    db.commit(); db.close()
    import wlib.views as v
    _il.reload(v)
    return v


def test_agents_payload_old_db_without_bytes_recv(tmp_path, monkeypatch):
    """Regression: agents_payload must not raise 'near bytes_recv: syntax error' on a DB predating the column."""
    v = _agents_db_without_bytes(tmp_path, monkeypatch)
    out = v.agents_payload()                       # used to raise sqlite3.OperationalError
    assert out["conns"] and out["conns"][0]["bytes_recv"] == 0
    assert out["dests"] and out["dests"][0]["bytes_recv"] == 0
