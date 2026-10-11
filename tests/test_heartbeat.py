"""heartbeat.py: sshd/console parsing, self-key tagging, baseline-then-new, node batching, down/back alerts, and the
topology the Network map is drawn from."""
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SELF = "SHA256:selfkeyAAAA"


@pytest.fixture()
def hb(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test, lan: [10.0.0.0/24], domain: example.com}\nnotify: {backend: none}\n"
        "hosts:\n  - {name: pve, kind: proxmox, ssh: root@10.0.0.2}\n  - {name: nas, kind: linux, ssh: admin@10.0.0.5}\n"
        "cloudflare: {zone_id: z1}\nsources: {cloudflared: {ssh: admin@10.0.0.5}, npm: {ssh: admin@10.0.0.5}}\n"
        "router: {ssh: root@10.0.0.1}\nnetwork: {subnets: {10.0.0.0/24: LAN}}\n")
    import wlib.config as c
    importlib.reload(c)
    import wlib.hosts, wlib.notify, wlib.views  # noqa: E401
    for m in (wlib.hosts, wlib.notify, wlib.views):
        importlib.reload(m)
    import heartbeat
    importlib.reload(heartbeat)
    sent = []
    monkeypatch.setattr(heartbeat, "send", lambda t: sent.append(t))
    monkeypatch.setattr(heartbeat, "own_keys", lambda: {SELF: "this box (id_ed25519)"})
    heartbeat.sent = sent
    return heartbeat


def test_parse_formats_and_self(hb):
    text = "\n".join([
        f"1791722973.0 pve sshd-session[1]: Accepted publickey for root from 10.0.0.9 port 1 ssh2: ED25519 {SELF}",
        "1791722974.0 pve sshd-session[2]: Accepted publickey for root from 10.0.0.50 port 2 ssh2: ED25519 SHA256:other",
        "1791722975.0 pve sshd[3]: Accepted password for bob from 10.0.0.51 port 3 ssh2",
        "Oct 11 12:00:01 pve sshd[9]: Failed password for invalid user admin from 1.2.3.4 port 5 ssh2",
        "Oct 11 12:00:01 pve sshd[9]: Invalid user admin from 1.2.3.4 port 5",
        "2026-10-11T12:00:03.123456+01:00 pve sshd[9]: Failed publickey for root from 5.6.7.8 port 9 ssh2: RSA SHA256:x",
        "garbage line that is not sshd",
        "@@last",
        "root     tty1                          2026-09-30T01:26:23+01:00 - down  (00:01)",
        "root     pts/0        10.0.0.50        2026-09-30T01:26:23+01:00 - down  (00:01)",
    ])
    ev = hb.parse(text, {SELF: "this box (id_ed25519)"})
    assert [e["self"] for e in ev if e["ok"] and e["method"] == "publickey"] == [1, 0]
    assert ev[1]["key_fp"] == "SHA256:other"
    assert sum(1 for e in ev if not e["ok"]) == 2            # "Invalid user" + its "Failed … invalid user" = one
    assert [e for e in ev if e["method"] == "console"][0]["src"] == "tty1"
    assert not [e for e in ev if e["src"] == "10.0.0.50" and e["method"] == "console"]   # pts lines come from sshd
    assert ev[0]["ts"] == "2026-10-11 12:49:33"


def test_split_node_sections(hb):
    out = "nodeline1\nnodeline2\n@@ct:101\nct101line\n@@ct:102\n"
    parts = hb.split_sections(out)
    assert parts[None] == "nodeline1\nnodeline2" and parts["ct:101"] == "ct101line" and parts["ct:102"] == ""


def test_baseline_then_new_signin(hb):
    con = hb.db()
    first = [dict(ts="2026-10-01 10:00:00", user="root", src="10.0.0.50", method="publickey", key_fp="SHA256:k", ok=1, self=0)]
    assert hb.store(con, "node:10.0.0.2", first, "t") == []                  # baseline: silent
    again = first + [dict(ts="2026-10-02 10:00:00", user="root", src="10.0.0.50", method="publickey", key_fp="SHA256:k",
                          ok=1, self=0)]
    assert hb.store(con, "node:10.0.0.2", again, "t") == []                  # known pair, duplicate event ignored
    n = con.execute("select n from login_pairs where src='10.0.0.50'").fetchone()[0]
    assert n == 2
    fresh = hb.store(con, "node:10.0.0.2", [dict(ts="2026-10-03 10:00:00", user="root", src="203.0.113.7",
                                                 method="password", key_fp="", ok=1, self=0)], "t")
    assert fresh and fresh[0][2] == "203.0.113.7"
    own = hb.store(con, "node:10.0.0.2", [dict(ts="2026-10-03 11:00:00", user="root", src="10.0.0.9",
                                               method="publickey", key_fp=SELF, ok=1, self=1)], "t")
    assert own == []                                                         # warden's own key is never "new"


def fake_remote(answers):
    def remote(t, cmd, timeout=300, binary=False, root=False, stdin=None):
        a = answers[t["target"]]
        return a if isinstance(a, tuple) else (0, a, "")
    return remote


def test_beat_node_covers_containers_and_alerts(hb, monkeypatch):
    lxc = json.dumps([{"vmid": 101, "name": "web", "status": "running", "uptime": 5000},
                      {"vmid": 102, "name": "old", "status": "stopped", "uptime": 0}])
    calls = []

    def remote(t, cmd, **kw):
        calls.append(t["target"])
        return fake_remote(answers)(t, cmd, **kw)
    answers = {"node:10.0.0.2": f"123456.7 99\n@@lxc\n{lxc}", "host:10.0.0.5": "800.0 1"}
    monkeypatch.setattr(hb.hosts, "remote", remote)
    con = hb.db()
    hb.beat(con)
    assert sorted(calls) == ["host:10.0.0.5", "node:10.0.0.2"]               # ONE call per node, not per container
    st = {r["target"]: r["state"] for r in con.execute("select target,state from hb")}
    assert st == {"node:10.0.0.2": "up", "ct:101": "up", "ct:102": "stopped", "host:10.0.0.5": "up"}
    assert hb.sent == []                                                     # never-seen-running stopped CT: silent
    # the NAS stops answering: no alert until down_after (3) misses, then exactly one
    answers["host:10.0.0.5"] = (255, "", "ssh: connect to host 10.0.0.5: No route to host")
    for _ in range(4):
        hb.beat(con)
    assert len([m for m in hb.sent if "nas" in m and "not answering" in m]) == 1
    # back, with a lower uptime than the outage → "it rebooted"
    answers["host:10.0.0.5"] = "60.0 1"
    hb.beat(con)
    assert any("is back" in m and "rebooted" in m for m in hb.sent)


def test_node_down_marks_containers_unknown_not_down(hb, monkeypatch):
    lxc = json.dumps([{"vmid": 101, "name": "web", "status": "running", "uptime": 5000}])
    answers = {"node:10.0.0.2": f"100.0 1\n@@lxc\n{lxc}", "host:10.0.0.5": "800.0 1"}
    monkeypatch.setattr(hb.hosts, "remote", fake_remote(answers))
    con = hb.db()
    hb.beat(con)
    answers["node:10.0.0.2"] = (255, "", "timeout")
    for _ in range(3):
        hb.beat(con)
    st = {r["target"]: r["state"] for r in con.execute("select target,state from hb")}
    assert st["ct:101"] == "unknown" and st["node:10.0.0.2"] == "down"
    assert len(hb.sent) == 1 and "pve" in hb.sent[0]                         # one message for the node, none per CT


def _docker_hb(tmp_path, monkeypatch, watch="[proxy, cloudflared]"):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test, lan: [10.0.0.0/24], domain: example.com}\nnotify: {backend: none}\n"
        f"hosts:\n  - {{name: nas, kind: docker, ssh: admin@10.0.0.5, watch_containers: {watch}}}\n"
        "cloudflare: {zone_id: z1}\n")
    import wlib.config as c
    importlib.reload(c)
    import wlib.hosts, wlib.notify, wlib.views  # noqa: E401
    for m in (wlib.hosts, wlib.notify, wlib.views):
        importlib.reload(m)
    import heartbeat
    importlib.reload(heartbeat)
    sent = []
    monkeypatch.setattr(heartbeat, "send", lambda t: sent.append(t))
    monkeypatch.setattr(heartbeat, "own_keys", lambda: {SELF: "this box (id_ed25519)"})
    heartbeat.sent = sent
    return heartbeat


def test_beat_docker_containers_one_by_one(tmp_path, monkeypatch):
    """A declared Docker container that was running and then stopped (the unless-stopped-after-reboot casualty) is
    flagged, even though its host is up."""
    hb = _docker_hb(tmp_path, monkeypatch)
    out = ["123.4 1\n@@docker\nproxy|running\ncloudflared|running\n"]

    def remote(t, cmd, **kw):
        assert "docker ps -a" in cmd
        return (0, out[0], "")
    monkeypatch.setattr(hb.hosts, "remote", remote)
    con = hb.db()
    hb.beat(con)
    assert {r["target"]: r["state"] for r in con.execute("select target,state from hb")} == {
        "host:10.0.0.5": "up", "ctr:nas:proxy": "up", "ctr:nas:cloudflared": "up"}
    assert hb.sent == []                                               # both running: baseline, nothing to say
    out[0] = "123.4 1\n@@docker\nproxy|exited\ncloudflared|running\n"  # the host OS update ran `docker stop` on proxy
    hb.beat(con)
    st = {r["target"]: r["state"] for r in con.execute("select target,state from hb")}
    assert st["ctr:nas:proxy"] == "stopped" and st["ctr:nas:cloudflared"] == "up"
    assert st["host:10.0.0.5"] == "up"                                 # the box itself still looks fine
    assert any("proxy" in m and "STOPPED" in m for m in hb.sent)


def test_docker_host_down_marks_containers_unknown(tmp_path, monkeypatch):
    """A docker host that stops answering leaves its containers unknown, never down — one message, not one per CT."""
    hb = _docker_hb(tmp_path, monkeypatch)
    out = ["123.4 1\n@@docker\nproxy|running\ncloudflared|running\n"]

    def remote(t, cmd, **kw):
        return (0, out[0], "")
    monkeypatch.setattr(hb.hosts, "remote", remote)
    con = hb.db()
    hb.beat(con)
    monkeypatch.setattr(hb.hosts, "remote", lambda t, cmd, **kw: (255, "", "timeout"))
    for _ in range(3):
        hb.beat(con)
    st = {r["target"]: r["state"] for r in con.execute("select target,state from hb")}
    assert st["host:10.0.0.5"] == "down"
    assert st["ctr:nas:proxy"] == "unknown" and st["ctr:nas:cloudflared"] == "unknown"
    assert len(hb.sent) == 1 and "nas" in hb.sent[0]                   # one message for the host, none per container


def test_views_heartbeat_and_topology(hb, monkeypatch):
    lxc = json.dumps([{"vmid": 101, "name": "web", "status": "running", "uptime": 5000}])
    monkeypatch.setattr(hb.hosts, "remote", fake_remote({"node:10.0.0.2": f"100.0 1\n@@lxc\n{lxc}", "host:10.0.0.5": "9.0 1"}))
    con = hb.db()
    hb.beat(con)
    hb.store(con, "ct:101", [dict(ts="2026-10-03 10:00:00", user="root", src="10.0.0.50", method="publickey",
                                  key_fp="SHA256:k", ok=1, self=0),
                             dict(ts="2026-10-03 10:05:00", user="root", src="10.0.0.9", method="publickey",
                                  key_fp=SELF, ok=1, self=1)], "t")
    con.commit()
    import wlib.views as v
    p = v.heartbeat_payload()
    row = next(r for r in p["heartbeat"] if r["target"] == "ct:101")
    assert row["last_login"]["src"] == "10.0.0.50"                         # the self-key sign-in is not "last login"
    assert all(r["src"] != "10.0.0.9" for r in p["logins"])
    t = v.topology()
    assert t["edge"] == {"cloudflare": True, "domain": "example.com", "tunnel": "10.0.0.5", "proxy": "10.0.0.5", "sso": False}
    assert t["gateway"]["ip"] == "10.0.0.1"
    pve = next(s for s in t["servers"] if s["name"] == "pve")
    assert pve["state"] == "up" and [c["target"] for c in pve["cts"]] == ["ct:101"] and pve["subnet"] == "10.0.0.0/24"
    assert t["subnets"][0]["label"] == "LAN"
