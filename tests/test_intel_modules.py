"""Offline tests for the log/edge/intel side of warden (no network, no SSH).

Each test points WARDEN_HOME at a temp dir and reloads wlib.config, so nothing
touches a real install."""
import importlib
import json
import sqlite3
import subprocess
import sys
import urllib.request
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


def test_allowlist_guards_read_self_ips(home):
    (home / "self-ips.txt").write_text("# our dynamic WAN lease\n203.0.113.7\n")
    w = load("warden")
    allow = w.allow_extra(w.load_conf())
    assert "203.0.113.7" in allow                        # self-ips.txt is part of the set
    assert w.is_allowlisted("203.0.113.7", allow)
    assert w.net_overlaps_allow("203.0.113.0/24", allow)         # own WAN's /24 refused
    assert not w.net_overlaps_allow("198.51.100.0/24", allow)    # hostile /24 still bannable


def test_unconfigured_sources_are_skipped(home, monkeypatch):
    w = load("warden")
    no_subprocess(monkeypatch)
    con = w.db()
    assert w.collect_npm(con) == ([], 0, None)
    assert w.collect_authelia(con) == ([], 0, None)
    assert w.collect_cloudflared(con) == ([], 0, None)
    assert w.collect_caddy(con) == ([], 0, None)
    assert w.collect_traefik(con) == ([], 0, None)
    assert w.collect_authentik(con) == ([], 0, None)


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


def test_docker_logs_collector_is_uncapped(home, monkeypatch):
    (home / "warden.yml").write_text("sources:\n  cloudflared: {ssh: local, container: cloudflared}\n")
    w = load("warden")
    seen = []

    class P:
        returncode, stdout = 0, ""

    def fake(argv, **k):
        seen.append(argv)
        return P()
    monkeypatch.setattr(subprocess, "run", fake)
    con = w.db()
    w.collect_cloudflared(con)
    cmd = seen[0][2]
    assert "--since" in cmd
    assert "tail" not in cmd


def test_docker_logs_collector_keeps_every_line(home, monkeypatch):
    (home / "warden.yml").write_text("sources:\n  cloudflared: {ssh: local, container: cloudflared}\n")
    w = load("warden")
    big = "\n".join(
        "2026-10-11T12:00:00Z INF dest=https://example.com/wp-login.php ip=198.41.1.1"
        for _ in range(1000)
    )
    monkeypatch.setattr(w, "src_sh", lambda *a, **k: big)
    con = w.db()
    lines, _, _ = w.collect_cloudflared(con)
    assert len(lines) == 1000


def test_broken_ssh_is_blind_not_quiet(home, monkeypatch):
    (home / "warden.yml").write_text("sources:\n  npm: {ssh: me@nas}\n")
    w = load("warden")

    class Fail:
        returncode, stdout = 1, ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Fail())
    con = w.db()
    lines, nbytes, note = w.collect_npm(con)
    assert (lines, nbytes) == ([], 0)
    assert note == "BLIND: ssh to me@nas failed"


def test_quiet_source_is_not_blind(home, monkeypatch):
    (home / "warden.yml").write_text("sources:\n  npm: {ssh: me@nas}\n")
    w = load("warden")

    class Ok:
        returncode, stdout = 0, "10\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Ok())
    con = w.db()
    w.wm_set(con, "npm", 10)            # watermark already at the end of the file
    assert w.collect_npm(con) == ([], 0, None)


def test_failed_tail_does_not_advance_watermark(home, monkeypatch):
    (home / "warden.yml").write_text("sources:\n  npm: {ssh: me@nas}\n")
    w = load("warden")

    class Ok:
        returncode, stdout = 0, "10\n"

    class Fail:
        returncode, stdout = 1, ""

    def fake(argv, **k):
        return Ok() if "wc -c" in argv[-1] else Fail()

    monkeypatch.setattr(subprocess, "run", fake)
    con = w.db()
    lines, nbytes, note = w.collect_npm(con)
    assert note == "BLIND: ssh to me@nas failed"
    assert w.wm_get(con, "npm") is None       # unread lines are not dropped


# ── warden.py cf_ban: the current Cloudflare enforcement API ────────────────
class FakeResp:
    def __init__(self, payload):
        self._data = payload

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeCF:
    def __init__(self, extra=None, apply_put=True):
        self.rules = list(extra or [])
        self.calls = []
        self.apply_put = apply_put

    def urlopen(self, req, timeout=None):
        method = req.get_method()
        body = json.loads(req.data) if req.data else None
        self.calls.append((method, req.full_url, body))
        if method == "PUT" and self.apply_put:
            self.rules = body["rules"]
        payload = json.dumps({"success": True, "result": {"id": "rs1", "rules": list(self.rules)}}).encode()
        return FakeResp(payload)


class FakeCFRequests:                              # edgeban.py talks to Cloudflare over requests
    def __init__(self, extra=None):
        self.rules = list(extra or [])
        self.calls = []

    def request(self, method, url, **kw):
        body = kw.get("json")
        path = url.split("/client/v4", 1)[1] if "/client/v4" in url else url
        self.calls.append((method, path, body))
        if method == "PUT":
            self.rules = body["rules"]

        class Resp:
            @staticmethod
            def json():
                return {"success": True, "result": {"id": "rs1", "rules": list(self.rules)}}
        return Resp()


def _cf_home(home, monkeypatch):
    (home / "warden.yml").write_text(
        "cloudflare:\n  zone_id: 0123456789abcdef0123456789abcdef\n  token_secret: CF_API_TOKEN\n")
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    w = load("warden")
    client = FakeCF(extra=[{"id": "x", "action": "challenge", "expression": 'http.request.uri.path contains "/admin"',
                            "description": "existing rule", "enabled": True}])
    monkeypatch.setattr(urllib.request, "urlopen", client.urlopen)
    return w, client


def test_cf_ban_uses_waf_custom_rules(home, monkeypatch):
    w, client = _cf_home(home, monkeypatch)
    ok, msg = w.cf_ban("203.0.113.9", "sqli", {})
    assert ok and "updated" in msg
    assert not any("firewall/access_rules" in c[1] for c in client.calls)
    assert client.calls[0][1].endswith("/rulesets/phases/http_request_firewall_custom/entrypoint")
    put = next(c for c in client.calls if c[0] == "PUT")
    block = next(r for r in put[2]["rules"] if r["description"] == w.DESC)
    assert block["action"] == "block" and block["expression"] == "(ip.src in {203.0.113.9})"
    assert any(r["description"] == "existing rule" for r in put[2]["rules"])


def test_cf_ban_appends_without_duplicates(home, monkeypatch):
    w, client = _cf_home(home, monkeypatch)
    assert w.cf_ban("203.0.113.9", "sqli", {})[0]
    assert w.cf_ban("203.0.113.9", "sqli", {})[0]
    assert w.cf_ban("198.51.100.0/24", "spread", {})[0]
    puts = [c for c in client.calls if c[0] == "PUT"]
    block = next(r for r in puts[-1][2]["rules"] if r["description"] == w.DESC)
    assert block["expression"] == "(ip.src in {203.0.113.9 198.51.100.0/24})"


def test_cf_ban_needs_credentials(home):
    w = load("warden")
    ok, msg = w.cf_ban("203.0.113.9", "sqli", {})
    assert not ok and "credentials" in msg


def test_cf_unban_removes_address(home, monkeypatch):
    w, client = _cf_home(home, monkeypatch)
    assert w.cf_ban("203.0.113.9", "sqli", {})[0]
    assert w.cf_ban("198.51.100.0/24", "spread", {})[0]
    ok, msg = w.cf_unban("203.0.113.9", {})
    assert ok and "updated" in msg
    puts = [c for c in client.calls if c[0] == "PUT"]
    block = next(r for r in puts[-1][2]["rules"] if r["description"] == w.DESC)
    assert block["expression"] == "(ip.src in {198.51.100.0/24})"


def test_cf_ban_shape_matches_edgeban_sync(home, monkeypatch):
    """cf_ban's requests are byte-for-byte the ones edgeban.py sync produces —
    the shape the owner validates with `edgeban.py sync` against a live account."""
    w, wclient = _cf_home(home, monkeypatch)
    assert w.cf_ban("203.0.113.9", "sqli", {})[0]

    eb = load("edgeban")
    eclient = FakeCFRequests(extra=[
        {"id": "x", "action": "challenge", "expression": 'http.request.uri.path contains "/admin"',
         "description": "existing rule", "enabled": True}])
    monkeypatch.setattr(eb.requests, "request", eclient.request)
    con = eb.db()
    con.execute("insert into edge_bans(target, reason, score, status, created) "
                "values('203.0.113.9', 'sqli', 20, 'active', datetime('now'))")
    con.commit()
    assert "1 entry" in eb.sync(con)

    wshape = [(m, u.split("/client/v4", 1)[1] if "/client/v4" in u else u, b)
              for m, u, b in wclient.calls]
    assert wshape == eclient.calls


def test_cf_ban_catches_a_write_that_does_not_land(home, monkeypatch):
    """cf_ban must not claim a ban it did not verify: when the endpoint accepts
    the PUT but the read-back shows the rule unchanged, cf_ban fails loudly
    rather than pretending the ban is in place."""
    w, client = _cf_home(home, monkeypatch)
    client.apply_put = False                      # simulate an endpoint that silently drops the write
    ok, msg = w.cf_ban("203.0.113.9", "sqli", {})
    assert not ok and "read-back" in msg


def test_expire_lapsed_unbans_only_expired(home, monkeypatch):
    w, client = _cf_home(home, monkeypatch)
    client.rules.append({"id": "b", "action": "block",
                         "expression": "(ip.src in {203.0.113.9 198.51.100.4})",
                         "description": w.DESC, "enabled": True})
    con = w.db()
    con.execute("insert into bans(ts,ip,score,reasons,state,expires,note) "
                "values(datetime('now'), '203.0.113.9', 20, 'sqli', 'active', "
                "datetime('now','-1 hour'), 'cf-edge blocked')")
    con.execute("insert into bans(ts,ip,score,reasons,state,expires,note) "
                "values(datetime('now'), '198.51.100.4', 20, 'traversal', 'active', "
                "datetime('now','+1 hour'), 'cf-edge blocked')")
    con.commit()
    assert w.expire_lapsed(con, w.load_conf()) == 1
    states = {r["ip"]: r["state"] for r in con.execute("select ip, state from bans")}
    assert states["203.0.113.9"] == "lapsed"
    assert states["198.51.100.4"] == "active"
    puts = [c for c in client.calls if c[0] == "PUT"]
    block = next(r for r in puts[-1][2]["rules"] if r["description"] == w.DESC)
    assert block["expression"] == "(ip.src in {198.51.100.4})"


def test_expire_lapsed_failed_unban_stays_active_and_retries(home, monkeypatch):
    """A failed unban leaves the row 'active' so the next sweep retries it —
    the unban path's failure behaviour, not just its happy path."""
    w = load("warden")
    con = w.db()
    con.execute("insert into bans(ts,ip,score,reasons,state,expires,note) "
                "values(datetime('now'), '203.0.113.9', 20, 'sqli', 'active', "
                "datetime('now','-1 hour'), 'cf-edge blocked')")
    con.commit()

    # no CF credentials → cf_unban fails → nothing unblocked, row still 'active'
    assert w.expire_lapsed(con, w.load_conf()) == 0
    row = con.execute("select state, note from bans where ip='203.0.113.9'").fetchone()
    assert row["state"] == "active" and "unban failed" in row["note"]

    # next sweep with credentials → the same row is unblocked and marked 'lapsed'
    w, client = _cf_home(home, monkeypatch)
    client.rules.append({"id": "b", "action": "block",
                         "expression": "(ip.src in {203.0.113.9})",
                         "description": w.DESC, "enabled": True})
    assert w.expire_lapsed(con, w.load_conf()) == 1
    assert con.execute("select state from bans where ip='203.0.113.9'").fetchone()["state"] == "lapsed"


# ── the extra log formats (Caddy JSON, Traefik CLF, Authentik JSON) ─────────
CADDY = ('{"level":"info","ts":1704067200.0,"logger":"http.log.access","msg":"handled request",'
         '"request":{"remote_ip":"203.0.113.5","remote_port":"4321","proto":"HTTP/2.0",'
         '"method":"GET","host":"example.com","uri":"/wp-login.php",'
         '"headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64)"]}},"size":1234,"status":404}')
TRAEFIK = ('203.0.113.5 - - [11/Oct/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" '
           '404 153 "-" "Mozilla/5.0 (X11; Linux x86_64)" 1 "router@docker" "http://10.0.0.1:80" 3ms')
AUTHENTIK = ('{"event": "Created Event", "level": "info", "logger": "authentik.events.models",'
             ' "action": "login_failed", "client_ip": "203.0.113.6",'
             ' "user": {"pk": 2, "email": "", "username": "AnonymousUser"},'
             ' "timestamp": "2026-10-11T12:00:00.000000Z"}')


def test_caddy_scorer(home):
    w = load("warden")
    ev = w.score_caddy(CADDY)
    assert ev["ip"] == "203.0.113.5" and "wordpress-probe" in ev["kind"] and ev["score"] >= 3
    assert w.score_caddy('{"msg": "something else"}') is None


def test_traefik_scorer(home):
    w = load("warden")
    ev = w.score_traefik(TRAEFIK)
    assert ev["ip"] == "203.0.113.5" and "wordpress-probe" in ev["kind"]


def test_authentik_scorer(home):
    w = load("warden")
    ev = w.score_authentik(AUTHENTIK)
    assert ev["ip"] == "203.0.113.6" and ev["kind"] == "auth-failure" and ev["score"] == 3
    assert w.score_authentik('{"action": "login", "client_ip": "203.0.113.6"}') is None
    assert w.score_authentik("not json") is None


def test_new_source_event_times(home):
    w = load("warden")
    assert w.event_time("caddy", CADDY) == "2024-01-01 00:00:00"
    assert w.event_time("traefik", TRAEFIK) == "2026-10-11 12:00:00"
    assert w.event_time("authentik", AUTHENTIK) == "2026-10-11 12:00:00"


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

    def resolve(self, mid, line):          # outcome written into the original message (recorded like a reply)
        self.posts.append((line, mid))
        return True

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
