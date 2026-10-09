"""Host inventory + the modules built on it (vulnscan, patcher, images, integrity, harden). No network."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wlib import config, hosts, secrets  # noqa: E402

SAMPLE = """
estate: {timezone: Europe/London, self_target: "ct:100"}
hosts:
  - name: pve1
    kind: proxmox
    ssh: root@10.0.0.2
    docker_cts: [104]
    patch: true
  - name: pve2
    kind: proxmox
    ssh: root@10.0.0.3
    discover: false
    patch: true
  - name: nas
    kind: docker
    ssh: admin@10.0.0.5
    firmware: zimaos
  - name: llm
    kind: linux
    ssh: me@10.0.0.6
    sudo_secret: LLM_SUDO
  - name: box
    kind: local
    docker: true
roles: {"ct:100": "the hub"}
core: ["ct:100", "ctr:nas:proxy"]
patch: {night: "02:30"}
"""

PCT_LIST = "100        running                 hub\n101        stopped                 old\n104        running                 docker\n"


@pytest.fixture
def estate(tmp_path, monkeypatch):
    conf = tmp_path / "warden.yml"
    conf.write_text(SAMPLE)
    monkeypatch.setattr(config, "CONF", conf)
    monkeypatch.setattr(config, "DATA", tmp_path)
    monkeypatch.setattr(config, "DB", str(tmp_path / "warden.db"))
    config.cfg(reload=True)
    calls = []

    def fake_run(cmd, timeout=300, binary=False, inp=None):
        calls.append({"cmd": cmd, "inp": inp})
        if cmd[-1] == "pct list | tail -n +2":
            return 0, PCT_LIST, ""
        return 0, "ok", ""
    monkeypatch.setattr(hosts, "run", fake_run)
    yield calls
    config.cfg(reload=True)


def test_target_ids(estate):
    ids = [t["target"] for t in hosts.targets()]
    assert ids == ["node:10.0.0.2", "ct:100", "ct:104", "img:ct104", "node:10.0.0.3",
                   "img:nas", "fw:nas", "host:10.0.0.6", "host:local", "img:box"]
    kinds = {t["target"]: t["kind"] for t in hosts.targets()}
    assert kinds["ct:100"] == "ct" and kinds["img:nas"] == "images" and kinds["fw:nas"] == "firmware"
    assert kinds["host:10.0.0.6"] == "host" and kinds["host:local"] == "local"
    ct = next(t for t in hosts.targets() if t["target"] == "ct:104")
    assert ct["node"] == "10.0.0.2" and ct["vmid"] == 104 and ct["ssh"] == "root@10.0.0.2" and ct["patchable"] == 1
    # stopped CTs are not targets; discover:false skips pct list
    assert not any(c["cmd"][-2:] == ["root@10.0.0.3", "pct list | tail -n +2"] for c in estate)


def test_remote_argv_shapes(estate, monkeypatch):
    ts = {t["target"]: t for t in hosts.targets()}
    estate.clear()
    hosts.remote(ts["node:10.0.0.2"], "uname -r")
    assert estate[-1]["cmd"] == hosts.SSH + ["root@10.0.0.2", "uname -r"]
    hosts.remote(ts["ct:100"], "echo 'x'")
    assert estate[-1]["cmd"] == hosts.SSH + ["root@10.0.0.2", "pct exec 100 -- sh -c 'echo '\"'\"'x'\"'\"''"]
    hosts.remote(ts["img:ct104"], "docker ps")
    assert estate[-1]["cmd"] == hosts.SSH + ["root@10.0.0.2", "pct exec 104 -- sh -c 'docker ps'"]
    hosts.remote(ts["img:nas"], "docker ps")
    assert estate[-1]["cmd"] == hosts.SSH + ["admin@10.0.0.5", "docker ps"]
    # plain host, read-only: no sudo
    hosts.remote(ts["host:10.0.0.6"], "cat /etc/os-release")
    assert estate[-1]["cmd"] == hosts.SSH + ["me@10.0.0.6", "cat /etc/os-release"] and estate[-1]["inp"] is None
    # plain host as root: sudo -S, password over stdin, never in argv
    monkeypatch.setenv("LLM_SUDO", "s3cret")
    hosts.remote(ts["host:10.0.0.6"], "apt-get -s full-upgrade", root=True)
    assert estate[-1]["cmd"] == hosts.SSH + ["me@10.0.0.6", "sudo -S -p '' sh -c 'apt-get -s full-upgrade'"]
    assert estate[-1]["inp"] == "s3cret\n" and "s3cret" not in " ".join(estate[-1]["cmd"])
    # local: no ssh at all
    hosts.remote(ts["host:local"], "id -u")
    assert estate[-1]["cmd"] == ["sh", "-c", "id -u"]


def test_sudo_secret_missing_is_loud(estate, monkeypatch):
    monkeypatch.delenv("LLM_SUDO", raising=False)
    monkeypatch.setattr(secrets, "get", lambda name, default=None: default)
    t = next(t for t in hosts.targets() if t["target"] == "host:10.0.0.6")
    with pytest.raises(RuntimeError, match="LLM_SUDO"):
        hosts.remote(t, "true", root=True)


def test_docker_host_and_roles(estate):
    assert hosts.docker_host("img:ct104")["vmid"] == 104
    assert hosts.docker_host("img:nas")["ssh"] == "admin@10.0.0.5"
    assert hosts.roles()["ct:100"] == "the hub" and "ctr:nas:proxy" in hosts.core()
    assert hosts.self_target() == "ct:100"


def test_patcher_timing_rule(estate):
    import patcher
    t = {"target": "ct:104", "name": "docker"}
    assert patcher.timing_rule(t, [("curl", "", "")], (1, 0, 1))[0] == "now"            # KEV fixed → now
    assert patcher.timing_rule(t, [("curl", "", "")], (1, 1, 0))[0] == "now"            # critical → now
    assert patcher.timing_rule(t, [("linux-image-amd64", "", "")], (0, 0, 0))[0] == "tonight"
    assert patcher.timing_rule(t, [("curl", "", "")], (0, 0, 0))[0] == "now"
    assert patcher.timing_rule({"target": "ct:100", "name": "hub"}, [("curl", "", "")], (0, 0, 0))[0] == "tonight"
    assert patcher.timing_rule({"target": "ctr:nas:proxy", "name": "p"}, [("p", "", "")], (0, 0, 0))[0] == "tonight"
    # no advisor configured → the rule decides, and says so
    v, why = patcher.decide_timing(t, [("systemd", "", "")], [], (0, 0, 0))
    assert v == "tonight" and why.startswith("rule — reboot/restart likely")
    assert patcher.night() == (2, 30)


def test_patcher_advisor_optional(estate, monkeypatch, tmp_path):
    import patcher
    (tmp_path / "myadv.py").write_text(
        "class D:\n    value='tonight'; confidence=0.9; probs={'tonight': 0.9}\n"
        "def choose(*a, **k):\n    return D()\n")
    monkeypatch.setitem(config.cfg()["patch"], "advisor", "myadv")
    monkeypatch.setitem(config.cfg()["patch"], "advisor_path", str(tmp_path))
    v, why = patcher.decide_timing({"target": "ct:104", "name": "d"}, [("curl", "", "")], [], (0, 0, 0))
    assert v == "tonight" and why.startswith("Myadv p=0.90")
    monkeypatch.setitem(config.cfg()["patch"], "advisor", "does_not_exist_xyz")
    v, why = patcher.decide_timing({"target": "ct:104", "name": "d"}, [("curl", "", "")], [], (0, 0, 0))
    assert v == "now" and why.startswith("rule — ")


def test_patcher_remote_uses_root(estate, monkeypatch):
    import patcher
    monkeypatch.setenv("LLM_SUDO", "pw")
    t = next(t for t in hosts.targets() if t["target"] == "host:10.0.0.6")
    rc, out = patcher.remote(t, "apt-get update")
    assert rc == 0 and estate[-1]["cmd"][-1].startswith("sudo -S")
    with pytest.raises(ValueError):
        patcher.remote({"kind": "images"}, "x")


def test_images_hosts_from_inventory(estate, monkeypatch):
    import images
    line = "web|nginx:latest|newer|/srv/app|web|2026-10-01|abcdef123456\n"
    monkeypatch.setattr(hosts, "run", lambda cmd, **k: (0, line, ""))
    rows = images.facts("img:nas")
    assert rows == [["web", "nginx:latest", "newer", "/srv/app", "web", "2026-10-01", "abcdef123456"]]


def test_vulnscan_firmware_unknown_kind(estate):
    import vulnscan
    label, cur, latest, note = vulnscan.firmware({"firmware": "acmeos", "ssh": "x@y", "kind": "firmware"})
    assert cur is None and latest is None and "skipped" in note


def test_modules_import_without_estate_paths():
    for m in ("vulnscan", "patcher", "images", "integrity", "harden"):
        src = open(os.path.join(ROOT, m + ".py")).read()
        for bad in ("/opt/warden", "/opt/hermes-agent", "/root/.hermes", "toolsmith_discord", "hermes_secrets"):
            assert bad not in src, (m, bad)


def test_appliance_root_via_docker(estate, monkeypatch, tmp_path):
    """ZimaOS-style box: no sudo, docker group = root. Read-only stays plain; root goes through a throwaway container."""
    conf = tmp_path / "warden.yml"
    text = SAMPLE.replace("  - name: box\n", "  - name: zima\n    kind: linux\n    ssh: admin@10.0.0.7\n    docker: true\n"
                          "    firmware: zimaos\n    root_via: docker\n    os_scan: false\n  - name: box\n")
    conf.write_text(text)
    config.cfg(reload=True)
    ts = {t["target"]: t for t in hosts.targets()}
    assert {"host:10.0.0.7", "img:zima", "fw:zima"} <= set(ts)
    assert ts["host:10.0.0.7"]["os_scan"] is False
    estate.clear()
    hosts.remote(ts["host:10.0.0.7"], "id -u")
    assert estate[-1]["cmd"] == hosts.SSH + ["admin@10.0.0.7", "id -u"]
    hosts.remote(ts["host:10.0.0.7"], "id -u", root=True)
    cmd = estate[-1]["cmd"][-1]
    assert cmd.startswith("docker run --rm -i --privileged --pid=host --net=host -v /:/host alpine:latest chroot /host sh -c ")
    assert "sudo" not in cmd


def test_cfsec_geo_never_blocks_own_country(estate, monkeypatch, tmp_path):
    import json as _j
    import cfsec
    monkeypatch.setattr(cfsec, "GEO_WANT", tmp_path / "geo-block.json")
    monkeypatch.setattr(cfsec, "GEO_DONE", tmp_path / "geo-applied.json")
    (tmp_path / "geo-block.json").write_text(_j.dumps({"enabled": True, "block": ["GB", "RU"]}))
    monkeypatch.setattr(cfsec, "own_countries", lambda: {"GB"})
    called = []
    monkeypatch.setattr(cfsec, "call", lambda *a, **k: called.append(a) or (True, {"result": {"id": "r", "rules": []}}))
    assert cfsec.apply_geo("tok", True, record=True) == 2 and not called          # refused before any API call
    assert "GB" in _j.loads((tmp_path / "geo-applied.json").read_text())["msg"]
    (tmp_path / "geo-block.json").write_text(_j.dumps({"enabled": False, "block": ["RU"]}))
    assert cfsec.geo_rule() is None and cfsec.geo_desired() == (False, ["RU"])
