"""agents.py — classifying which Hermes agent made a connection, ignoring out-of-scope processes, parsing the
collector, and the threat-feed / new-destination paths (all offline: ss and the feeds are faked)."""
import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def ag(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test, timezone: Europe/London, lan: [192.168.0.0/16]}\n"
        "notify: {backend: none}\nagents: {include_local: true, learn_hours: 48}\n")
    import wlib.config as c
    importlib.reload(c)
    import wlib.hosts, wlib.notify  # noqa: E401
    for m in (wlib.hosts, wlib.notify):
        importlib.reload(m)
    import agents
    importlib.reload(agents)
    return agents


def test_classify_hermes_opencode_app_other(ag):
    assert ag.classify("/usr/local/bin/hermes --profile coder -z hi")[0] == "hermes:coder"
    assert ag.classify("hermes -z hi")[0] == "hermes:default"
    assert ag.classify("/usr/local/bin/opencode run x", uid_name="steward")[0] == "opencode:steward"
    assert ag.classify("python3 -m instagram.agent")[0] == "app:instagram"
    assert ag.classify("python3 /opt/x/scraper.py --go")[0] == "app:scraper"   # crawl4ai/playwright keyword? no → app:scraper by name
    assert ag.classify("/usr/bin/curl https://x", exe="/usr/bin/curl")[0] == "other:curl"


def test_ignore_claude_and_system(ag):
    for cmd in ("node /usr/local/bin/claude", "claude --resume", "/usr/local/bin/claude-code",
                "sshd: root@pts/1", "/usr/lib/systemd/systemd-resolved", "cron"):
        assert ag.ignored(cmd), cmd
    for cmd in ("/usr/local/bin/hermes --profile sec -z x", "opencode run x", "python3 -m instagram.agent"):
        assert not ag.ignored(cmd), cmd


def test_config_ignore_extends(ag, tmp_path, monkeypatch):
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test}\nnotify: {backend: none}\nagents: {ignore: ['my-tool', '/^node /']}\n")
    import wlib.config as c
    importlib.reload(c)
    importlib.reload(ag)
    assert ag.ignored("run my-tool now")
    assert ag.ignored("node server.js")
    assert not ag.ignored("hermes --profile coder")


def test_is_internet(ag):
    assert ag.is_internet("1.2.3.4") and ag.is_internet("8.8.8.8")
    assert not ag.is_internet("192.168.1.5")     # LAN
    assert not ag.is_internet("10.0.0.1")        # private
    assert not ag.is_internet("100.64.0.1")      # CGNAT / NetBird
    assert not ag.is_internet("127.0.0.1")


SS = (
    "@@meta\thost=box\troot=1\tss=1\n"
    "@@total\t3\n"
    "@@conn\t1001\t8.8.8.8\t443\n"
    "@@conn\t1002\t1.2.3.4\t443\n"
    "@@conn\t1003\t192.168.0.9\t22\n"          # LAN → dropped by is_internet later
    "@@proc\t1001\t0\t\t/usr/bin/python3\t/usr/local/bin/hermes --profile scout -z go\n"
    "@@proc\t1002\t1100\tdocker-abc123def456\t/usr/bin/node\topencode run build\n"
)


def test_collect_parse(ag, monkeypatch):
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, SS, ""))
    meta, conns, procs = ag.collect({"target": "host:local", "kind": "local", "name": "x", "ssh": ""})
    assert meta["host"] == "box" and meta["root"] is True and meta["ss"] is True and meta["total"] == 3
    assert ("1001", "8.8.8.8", "443", 0) in conns and len(conns) == 3   # 4th field is bytes_recv (0 when absent)
    assert all(len(c) == 4 for c in conns)
    assert procs["1002"][1] == "docker-abc123def456"       # container from cgroup
    assert "hermes --profile scout" in procs["1001"][3]


# the collector now also carries bytes, permissions, sudo and sensitive-file facts
SS2 = (
    "@@meta\thost=box\troot=1\tss=1\n"
    "@@total\t2\n"
    "@@conn\t1001\t8.8.8.8\t443\t60123456\n"               # a real 57 MB download
    "@@conn\t1002\t1.2.3.4\t443\t512\n"
    "@@proc\t1001\t0\t\t/usr/bin/python3\thermes --profile scout -z go\n"
    "@@perm\t1001\t0\t0\t000001ffffffffff\t\n"             # root, full caps
    "@@perm\t1002\t1100\t1100\t0000000000000400\t1100 999\n"   # cap_net_bind_service, groups 1100 999
    "@@sudo\t0\tUser root may run the following commands: (ALL : ALL) ALL\n"
    "@@sudo\t1100\tnone or unknown\n"
    "@@file\t/etc/secret.env\t0:0:600\n"
)


def test_collect_parse_bytes_perms_files(ag, monkeypatch):
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, SS2, ""))
    meta, conns, procs = ag.collect({"target": "host:local", "kind": "local", "name": "x", "ssh": ""})
    assert ("1001", "8.8.8.8", "443", 60123456) in conns          # bytes carried through
    assert meta["perms"]["1001"] == ("0", "0", "000001ffffffffff", "")
    assert meta["perms"]["1002"] == ("1100", "1100", "0000000000000400", "1100 999")
    assert "(ALL : ALL) ALL" in meta["sudo"]["0"] and meta["sudo"]["1100"] == "none or unknown"
    assert meta["files"]["/etc/secret.env"] == "0:0:600"


def test_no_root_is_honest(ag, monkeypatch):
    out = "@@meta\thost=box\troot=0\tss=1\n@@total\t20\n@@conn\t9\t8.8.8.8\t443\n@@proc\t9\t0\t\t/x\thermes -z go\n"
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, out, ""))
    meta, conns, procs = ag.collect({"target": "host:local", "kind": "local", "name": "x", "ssh": ""})
    assert meta["root"] is False and meta["total"] == 20      # saw 20 sockets, attributed only what it could


def test_score_new_destination(ag):
    f = {"other_agents_using_it": 0, "hour": 3, "tld": "xyz", "domain": "evil.xyz", "port": 4444}
    s, why = ag.score(f)
    assert s >= ag.REVIEW_AT                                  # lonely + 3am + risky TLD + odd port → review
    f2 = {"other_agents_using_it": 3, "hour": 14, "tld": "com", "domain": "api.openrouter.ai", "port": 443}
    assert ag.score(f2)[0] < ag.LOG_AT                        # widely-used, business hours, normal → learned


def _prime(ag, monkeypatch, feodo_ip=None):
    monkeypatch.setattr(ag, "agent_targets", lambda: [{"target": "host:local", "kind": "local", "name": "box", "ssh": ""}])
    monkeypatch.setattr(ag.netintel, "refresh_feeds", lambda *a, **k: None)
    v4 = []
    if feodo_ip:
        import ipaddress
        x = int(ipaddress.IPv4Address(feodo_ip)); v4 = [(x, x, "feodo")]
    monkeypatch.setattr(ag.netintel, "load_feeds", lambda: ({}, v4))
    for name in ("post", "react", "resolve"):
        monkeypatch.setattr(ag.notify, name, lambda *a, **k: "mid")
    monkeypatch.setattr(ag.notify, "reactors", lambda *a, **k: None)
    monkeypatch.setattr(ag.notify, "owner", lambda: "owner")


def test_run_threat_alert(ag, monkeypatch):
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, SS, ""))
    _prime(ag, monkeypatch, feodo_ip="1.2.3.4")
    ag.run(dry=False)
    con = ag.db()
    al = con.execute("select agent, kind, feed, dest_ip from agent_alerts").fetchall()
    assert len(al) == 1 and al[0]["kind"] == "c2" and al[0]["feed"] == "feodo" and al[0]["dest_ip"] == "1.2.3.4"
    assert al[0]["agent"] == "opencode:?" or al[0]["agent"].startswith("opencode")
    # the hermes connection to 8.8.8.8 is clean and recorded, not alerted
    assert con.execute("select count(*) from agent_conns where agent like 'hermes:%'").fetchone()[0] == 1
    # a known-bad destination is never also scored as a 'new destination' finding
    assert con.execute("select count(*) from agent_findings where dest='1.2.3.4'").fetchone()[0] == 0


def test_first_run_is_silent_baseline(ag, monkeypatch):
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, SS, ""))
    _prime(ag, monkeypatch)                                   # no bad ip
    ag.run(dry=False)
    con = ag.db()
    # agents just first-seen → nothing is past the learn window yet → no findings, no alerts
    assert con.execute("select count(*) from agent_findings").fetchone()[0] == 0
    assert con.execute("select count(*) from agent_alerts").fetchone()[0] == 0
    assert con.execute("select count(*) from agent_conns").fetchone()[0] == 2   # two internet dests recorded


def test_classify_is_config_driven(ag, tmp_path, monkeypatch):
    # owner names their own agents in warden.yml; $1 expands to a capture group; built-ins still work as a fallback
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test}\nnotify: {backend: none}\n"
        "agents:\n  patterns:\n    - {pattern: '\\bmuse\\b', name: 'muse'}\n"
        "    - {pattern: 'mybot --role (\\w+)', name: 'mybot:$1'}\n")
    import wlib.config as c
    importlib.reload(c)
    importlib.reload(ag)
    assert ag.classify("node /opt/muse/run.js")[0] == "muse"
    assert ag.classify("python3 mybot --role writer")[0] == "mybot:writer"
    assert ag.classify("/usr/local/bin/hermes --profile sec -z x")[0] == "hermes:sec"   # built-in still matches
    assert ag.classify("/usr/bin/weird", exe="/usr/bin/weird")[0] == "other:weird"


def test_bad_pattern_is_skipped_not_fatal(ag, tmp_path, monkeypatch):
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test}\nnotify: {backend: none}\n"
        "agents:\n  patterns:\n    - {pattern: '(', name: 'broken'}\n    - {pattern: '\\bgood\\b', name: 'good'}\n")
    import wlib.config as c
    importlib.reload(c)
    importlib.reload(ag)                                      # must not raise on the invalid regex
    assert ag.classify("run good now")[0] == "good"


def test_run_stores_bytes_perms_files(ag, monkeypatch):
    monkeypatch.setattr(ag.hosts, "remote", lambda t, cmd, **k: (0, SS2, ""))
    _prime(ag, monkeypatch)
    ag.run(dry=False)
    con = ag.db()
    row = con.execute("select bytes_recv from agent_conns where dest='8.8.8.8'").fetchone()
    assert row["bytes_recv"] == 60123456                      # the download volume was recorded
    p = con.execute("select agent, root, caps from agent_perms where agent like 'hermes:%'").fetchone()
    assert p and p["root"] == 1 and p["caps"] == "000001ffffffffff"
    assert con.execute("select stat from agent_files where path='/etc/secret.env'").fetchone()["stat"] == "0:0:600"
