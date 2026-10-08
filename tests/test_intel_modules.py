"""Offline tests for the log/edge/intel side of warden (no network, no SSH).

Each test points WARDEN_HOME at a temp dir and reloads wlib.config, so nothing
touches a real install."""
import importlib
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def home(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("WARDEN_HOME", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path / "data"))
    monkeypatch.delenv("WARDEN_LOG_HOST", raising=False)
    monkeypatch.delenv("CROWDSEC_HOST", raising=False)
    import wlib.config
    importlib.reload(wlib.config)
    return tmp_path


def load(name):
    if name in sys.modules:
        return importlib.reload(sys.modules[name])
    return importlib.import_module(name)


def no_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"unexpected subprocess: {a[0] if a else k}")
    monkeypatch.setattr(subprocess, "run", boom)


# ── warden.py: config + the allowlist guards edgeban relies on ──────────────
def test_load_conf_defaults(home):
    w = load("warden")
    c = w.load_conf()
    assert c == {"enforce": False, "ban_threshold": 12, "max_bans_per_run": 3, "window_minutes": 60,
                 "allow": [], "ban_hours": 24, "subnet_threshold": 20, "subnet_min_ips": 3}


def test_load_conf_reads_yaml(home):
    (home / "warden.yml").write_text("enforce: true\nban_threshold: 9\nallow:\n  - 203.0.113.7\n  - 198.51.100.0/24\n")
    w = load("warden")
    c = w.load_conf()
    assert c["enforce"] is True and c["ban_threshold"] == 9
    assert c["allow"] == ["203.0.113.7", "198.51.100.0/24"]


def test_allowlist_guards(home):
    w = load("warden")
    assert w.is_allowlisted("192.168.1.5", [])            # private
    assert w.is_allowlisted("104.16.1.1", [])             # Cloudflare edge
    assert w.is_allowlisted("203.0.113.7", ["203.0.113.7"])
    assert not w.is_allowlisted("203.0.113.8", ["203.0.113.7"])
    assert w.net_overlaps_allow("203.0.113.0/24", ["203.0.113.7"])   # own IP inside a noisy /24
    assert not w.net_overlaps_allow("198.51.100.0/24", [])
    assert w.net_overlaps_allow("not-a-net", [])          # unparseable → never ban


def test_unconfigured_sources_are_skipped(home, monkeypatch):
    w = load("warden")
    no_subprocess(monkeypatch)
    con = w.db()
    assert w.collect_npm(con) == ([], 0)
    assert w.collect_authelia(con) == ([], 0)
    assert w.collect_cloudflared(con) == ([], 0)


def test_source_commands(home, monkeypatch):
    (home / "warden.yml").write_text(
        "sources:\n  npm: {ssh: me@nas}\n  authelia: {ssh: local, container: null, log: /var/log/authelia.log}\n")
    w = load("warden")
    seen = []

    class P:
        returncode, stdout = 0, "10\n"

    def fake(argv, **k):
        seen.append(argv)
        return P()
    monkeypatch.setattr(subprocess, "run", fake)
    con = w.db()
    w.collect_npm(con)
    assert seen[0][-2:] == ["me@nas", "docker exec npmplus sh -c 'wc -c < /data/nginx/logs/access.log'"]
    seen.clear()
    w.collect_authelia(con)
    assert seen[0] == ["sh", "-c", "wc -c < /var/log/authelia.log"]


# ── netintel / netids: optional vantage points ──────────────────────────────
def test_netintel_without_router(home, monkeypatch):
    ni = load("netintel")
    no_subprocess(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["netintel.py"])
    assert ni.main() == 0
    con = sqlite3.connect(str(home / "data" / "warden.db"))
    note = con.execute("select note from runs where source='adguard'").fetchone()[0]
    assert note == "skipped: no router configured"


def test_netintel_lan_from_config(home):
    (home / "warden.yml").write_text("estate:\n  lan: [10.9.0.0/16]\n")
    ni = load("netintel")
    assert ni.in_lan("10.9.3.4") and not ni.in_lan("192.168.1.4")


def test_netids_without_suricata(home, monkeypatch):
    nd = load("netids")
    no_subprocess(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["netids.py"])
    assert nd.main() == 0


# ── intel: Cloudflare + optional plug-ins ───────────────────────────────────
def test_intel_without_zone(home, monkeypatch):
    it = load("intel")
    no_subprocess(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["intel.py", "all"])
    assert it.main() == 0


def test_intel_plugins_skipped(home, monkeypatch):
    it = load("intel")
    no_subprocess(monkeypatch)
    snap = {"pages": [], "errors": []}
    it.pages(snap)
    it.sso_sites(snap)
    assert snap == {"pages": [], "errors": []}       # nothing ran, nothing reported as an error


def test_intel_sso_exempt_from_config(home):
    (home / "warden.yml").write_text('cloudflare:\n  sso_exempt:\n    auth.example.org: "is the SSO portal"\n')
    it = load("intel")
    assert it.accepted() == {"auth.example.org": "is the SSO portal"}


def test_exposure_diff_ignores_errored_sections(home):
    it = load("intel")
    prev = {"hosts": [{"name": "a.example.org", "kind": "tunnel", "content": "x"}], "errors": []}
    cur = {"hosts": [], "errors": ["dns: boom"]}
    assert it.exposure_diff(prev, cur) == []          # an API blip is not "everything went private"


# ── edgeban: the approval flow over wlib.notify ─────────────────────────────
class FakeNotify:
    APPROVE, REJECT = "✅", "❌"

    def __init__(self):
        self.posts, self.reacts, self.answer = [], [], {}

    def owner(self):
        return "owner-1"

    def post(self, text, channel=None, reply_to=None):
        self.posts.append((text, reply_to))
        return f"m{len(self.posts)}"

    def react(self, mid, emoji, channel=None):
        self.reacts.append((mid, emoji))

    def reactors(self, mid, emoji, channel=None):
        return ["owner-1"] if self.answer.get(mid) == emoji else []


def _seed_edgeban(home):
    w = load("warden")
    w.db().close()                                     # events/bans/runs/watermarks
    load("intel").db().close()                         # edge_events
    eb = load("edgeban")
    fake = FakeNotify()
    eb.td = fake
    return eb, fake


def test_edgeban_propose_then_approve(home, monkeypatch):
    eb, fake = _seed_edgeban(home)
    con = eb.db()
    con.execute("insert into bans(ts, ip, score, reasons, state) values(datetime('now'), '203.0.113.9', 20, "
                "'sqli', 'proposed')")
    con.commit()
    assert eb.cmd_propose(False) == 0
    row = eb.db().execute("select * from edge_bans").fetchone()
    assert row["target"] == "203.0.113.9" and row["status"] == "pending"
    assert ("m1", "✅") in fake.reacts and ("m1", "❌") in fake.reacts

    synced = []
    monkeypatch.setattr(eb, "sync", lambda con, dry=False: synced.append(1) or "rule now blocks 1 entry")
    fake.answer["m1"] = "✅"
    assert eb.cmd_poll() == 0
    assert eb.db().execute("select status from edge_bans").fetchone()[0] == "active"
    assert synced and "blocked at Cloudflare" in fake.posts[-1][0]


def test_edgeban_reject_and_allowlist(home, monkeypatch):
    (home / "warden.yml").write_text("allow:\n  - 203.0.113.0/24\n")
    eb, fake = _seed_edgeban(home)
    con = eb.db()
    con.execute("insert into bans(ts, ip, score, reasons, state) values(datetime('now'), '203.0.113.9', 20, "
                "'sqli', 'proposed')")
    con.execute("insert into bans(ts, ip, score, reasons, state) values(datetime('now'), '198.51.100.4', 20, "
                "'traversal', 'proposed')")
    con.commit()
    eb.cmd_propose(False)
    targets = [r[0] for r in eb.db().execute("select target from edge_bans")]
    assert targets == ["198.51.100.4"]                 # own range never proposed
    fake.answer["m1"] = "❌"
    monkeypatch.setattr(eb, "sync", lambda *a, **k: pytest.fail("sync on reject"))
    eb.cmd_poll()
    assert eb.db().execute("select status from edge_bans").fetchone()[0] == "rejected"


def test_edgeban_sync_needs_config(home):
    eb, _ = _seed_edgeban(home)
    with pytest.raises(RuntimeError, match="not configured"):
        eb.sync(eb.db())


# ── siemalert: CrowdSec location ────────────────────────────────────────────
def test_siemalert_crowdsec_argv(home):
    sa = load("siemalert")
    assert sa.crowdsec_argv("cscli x") is None
    (home / "warden.yml").write_text("sources:\n  crowdsec: {ssh: me@nas, container: crowdsec}\n")
    sa = load("siemalert")
    assert sa.crowdsec_argv("cscli x")[-2:] == ["me@nas", "docker exec crowdsec cscli x"]
