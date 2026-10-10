"""REST API, MCP connector, tokens, layout and approvals — against a throwaway database."""
import importlib
import json
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\nui: {auth: proxy}\n")
    con = sqlite3.connect(tmp_path / "warden.db")
    con.executescript("""
      create table events(id integer primary key, ts text, source text, ip text, kind text, detail text, score int);
      create table runs(id integer primary key, ts text, source text, lines int, parsed int, note text);
      create table bans(id integer primary key, ts text, ip text, score int, reasons text, state text, note text);
      create table net_hosts(mac text, ip text, hostname text, vendor text, first_seen text, last_seen text, approved int);
      create table net_ports(mac text, port int, service text);
      create table net_alerts(id integer primary key, ts text, kind text, mac text, ip text, detail text);
      create table net_runs(id integer primary key, ts text, hosts int);
      create table surface_snap(id integer primary key, ts text, data text);
      create table alert_suppressed(id integer primary key, ts text, kind text, detail text, reason text);
      insert into events(ts,source,ip,kind,detail,score) values
        (datetime('now','-1 hours'),'proxy','203.0.113.9','sensitive-file','/.env',8),
        (datetime('now','-2 hours'),'proxy','203.0.113.9','sqli','?id=1 or 1=1',8),
        (datetime('now','-3 hours'),'sso','198.51.100.4','auth-failure','bad password',3);
      insert into runs(ts,source,lines,parsed,note) values (datetime('now'),'proxy',100,3,'');
    """)
    con.commit(); con.close()
    import wlib.config as c
    importlib.reload(c)
    import wlib.notify, wlib.tokens, wlib.views, wlib.mcp, wlib.setup  # noqa: E401
    for m in (wlib.notify, wlib.tokens, wlib.views, wlib.mcp, wlib.setup):
        importlib.reload(m)
    spec = importlib.util.spec_from_file_location("warden_ui", ROOT / "warden-ui.py")
    ui = importlib.util.module_from_spec(spec); spec.loader.exec_module(ui)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ui.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{srv.server_port}", "tokens": wlib.tokens, "notify": wlib.notify,
           "mcp": wlib.mcp, "views": wlib.views}
    srv.shutdown()


def call(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            return r.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (json.loads(body) if body else None)


# ── REST ────────────────────────────────────────────────────────────────────
def test_v1_needs_a_token(env):
    assert call(env["url"] + "/api/v1/summary")[0] == 401
    assert call(env["url"] + "/api/v1/summary", headers={"Authorization": "Bearer wdn_nope"})[0] == 401


def test_v1_with_token(env):
    tok = env["tokens"].mint("test")
    h = {"Authorization": f"Bearer {tok}"}
    st, s = call(env["url"] + "/api/v1/summary", headers=h)
    assert st == 200 and s["mode"] == "detect-only" and s["kpi"]["events_24h"] == 3
    st, d = call(env["url"] + "/api/v1/detections?hours=24&min_score=5", headers=h)
    assert st == 200 and len(d["rows"]) == 2
    st, ip = call(env["url"] + "/api/v1/ip/203.0.113.9", headers=h)
    assert ip["score_30d"] == 16 and len(ip["events"]) == 2
    assert call(env["url"] + "/api/v1/nope", headers=h)[0] == 404
    assert "paths" in call(env["url"] + "/api/v1/openapi.json", headers=h)[1]
    assert env["tokens"].listing()[0]["uses"] >= 4


def test_token_hashed_and_revocable(env, tmp_path):
    tok = env["tokens"].mint("x")
    raw = sqlite3.connect(tmp_path / "warden.db").execute("select hash, hint from api_tokens").fetchone()
    assert tok not in raw[0] and tok not in raw[1]
    env["tokens"].revoke(env["tokens"].listing()[0]["id"])
    assert call(env["url"] + "/api/v1/summary", headers={"Authorization": f"Bearer {tok}"})[0] == 401


# ── browser writes ──────────────────────────────────────────────────────────
def test_writes_need_same_origin_header(env):
    assert call(env["url"] + "/api/layout", {"widgets": ["kind"]})[0] == 403
    assert call(env["url"] + "/api/tokens", {"name": "x"}, headers={"X-Warden": "layout"})[0] == 403
    st, _ = call(env["url"] + "/api/layout", {"widgets": ["kind"]},
                 headers={"X-Warden": "layout", "Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"})
    assert st == 403


def test_layout_roundtrip_drops_unknown(env):
    h = {"X-Warden": "layout"}
    st, r = call(env["url"] + "/api/layout", {"kpis": ["bans", "nope"], "widgets": ["vsev", "kind", "bogus", "kind"]},
                 headers=h)
    assert st == 200 and r["layout"]["widgets"] == ["vsev", "kind"] and r["layout"]["kpis"] == ["bans"]
    assert call(env["url"] + "/api")[1]["layout"]["widgets"] == ["vsev", "kind"]
    call(env["url"] + "/api/layout", {"reset": True}, headers=h)
    assert call(env["url"] + "/api")[1]["layout"]["widgets"] == env["views"].DEFAULT_LAYOUT["widgets"]


def test_dashboard_approval_counts_as_owner(env):
    n = env["notify"]
    mid = n.post("patch ct:101?")
    n.react(mid, n.APPROVE); n.react(mid, n.REJECT)
    assert n.reactors(mid, n.APPROVE) == []
    assert [a["id"] for a in n.pending()] == [mid]
    st, r = call(env["url"] + "/api/approvals", {"id": mid, "choice": "✅"}, headers={"X-Warden": "approvals"})
    assert r["ok"] and n.reactors(mid, n.APPROVE) == [n.owner()] and n.reactors(mid, n.REJECT) == []
    assert not n.decide(mid, n.REJECT)          # first decision wins
    assert n.pending() == []


# ── MCP ─────────────────────────────────────────────────────────────────────
def rpc(env, tok, msg):
    return call(env["url"] + "/mcp", msg, headers={"Authorization": f"Bearer {tok}"})


def test_mcp_handshake_and_tools(env):
    tok = env["tokens"].mint("mcp")
    assert call(env["url"] + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize"})[0] == 401
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
    assert r["result"]["protocolVersion"] == "2025-03-26" and r["result"]["serverInfo"]["name"] == "warden"
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert st == 202 and r is None                                   # trap 1
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in r["result"]["tools"]]
    assert "warden_summary" in names and "warden_lookup_ip" in names
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "warden_lookup_ip", "arguments": {"ip": "203.0.113.9"}}})
    assert not r["result"]["isError"] and json.loads(r["result"]["content"][0]["text"])["score_30d"] == 16


def test_mcp_tool_errors_are_results(env):
    tok = env["tokens"].mint("mcp")
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "warden_lookup_ip", "arguments": {}}})
    assert "error" not in r and r["result"]["isError"]               # trap 2
    st, r = rpc(env, tok, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "warden_detections", "arguments": {"hours": "lots"}}})
    assert r["result"]["isError"]


def test_mcp_get_is_405(env):
    assert call(env["url"] + "/mcp")[0] == 405                       # trap 3


def test_mcp_is_read_only(env):
    """No tool may change anything. A write tool belongs in a separate, separately-authorised server."""
    verbs = {"ban", "block", "unblock", "allow", "patch", "approve", "reject", "apply", "delete", "remove", "write",
             "set", "update", "commit", "revoke", "mint", "send", "post", "run", "exec", "accept", "enforce", "create"}
    for t in env["mcp"].TOOLS:
        words = set(t["name"].lower().split("_"))
        assert t["name"].startswith("warden_") and not words & verbs, t["name"]


# ── 2026-10-09: console edits, write-only secrets, country switch, CVE drawer ──
def test_config_override_allowlist(env, tmp_path):
    h = {"X-Warden": "config"}
    st, r = call(env["url"] + "/api/config", {"key": "api.public_url", "value": "https://w.example"}, headers=h)
    assert st == 200 and r["ok"]
    import wlib.config as c
    assert c.get("api.public_url") == "https://w.example"
    assert "public_url" in (tmp_path / "overrides.yml").read_text()
    assert "public_url" not in (tmp_path / "warden.yml").read_text()          # warden.yml never written
    for bad in ({"key": "enforce", "value": True}, {"key": "hosts", "value": "x"}, {"key": "secrets.backend", "value": "command"}):
        assert call(env["url"] + "/api/config", bad, headers=h)[0] == 400
    assert call(env["url"] + "/api/config", {"key": "notify.backend", "value": "smtp"}, headers=h)[0] == 400
    assert call(env["url"] + "/api/config", {"key": "api.public_url", "value": "x"})[0] == 403    # no header


def test_secret_is_write_only(env, tmp_path):
    st, r = call(env["url"] + "/api/secret", {"name": "DISCORD_BOT_TOKEN", "value": "s3cr3t-value"}, headers={"X-Warden": "secret"})
    assert st == 200 and r["ok"]
    f = tmp_path / "secrets.env"
    assert "DISCORD_BOT_TOKEN=s3cr3t-value" in f.read_text() and (f.stat().st_mode & 0o777) == 0o600
    assert call(env["url"] + "/api/secret", {"name": "X", "value": "a\nB=c"}, headers={"X-Warden": "secret"})[0] == 400
    for path in ("/api/settings", "/api"):
        st, body = call(env["url"] + path)
        assert "s3cr3t-value" not in json.dumps(body)


def test_geo_switch_validates_and_records(env, tmp_path):
    import wlib.config as c
    h = {"X-Warden": "geo"}
    assert call(env["url"] + "/api/geo", {"enabled": True, "block": ["RU"]}, headers=h)[1]["ok"] is False   # no zone
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\nui: {auth: proxy}\ncloudflare: {zone_id: z1}\n")
    c.cfg(reload=True)
    assert call(env["url"] + "/api/geo", {"enabled": True, "block": ["RUS"]}, headers=h)[0] == 400
    assert call(env["url"] + "/api/geo", {"enabled": True, "block": "RU"}, headers=h)[0] == 400
    st, r = call(env["url"] + "/api/geo", {"enabled": True, "block": ["ru", "KP", "ru"]}, headers=h)
    assert st == 200 and r["state"]["block"] == ["KP", "RU"]
    red = env["views"].redlist()
    assert red["enabled"] and red["block"] == ["KP", "RU"] and red["pending"]
    call(env["url"] + "/api/geo", {"enabled": False, "block": ["RU"]}, headers=h)
    red = env["views"].redlist()
    assert red["block"] == [] and red["chosen"] == ["RU"]                    # off keeps the choice, blocks nothing


def test_cve_view_and_tool(env, tmp_path):
    con = sqlite3.connect(tmp_path / "warden.db")
    con.executescript("""create table vulns(target text, vid text, pkg text, installed text, fixed text, severity text,
        title text, kev integer, status text, image text, descr text, url text);
      create table vuln_targets(target text primary key, name text);
      insert into vuln_targets values('ct:1','web');
      insert into vulns values('ct:1','CVE-2099-0001','openssl','3.0.1','3.0.2','CRITICAL','bad bug',1,'fixed','',
        'a long description','https://example.org/adv');""")
    con.commit(); con.close()
    r = env["views"].cve("CVE-2099-0001")
    assert r["kev"] and r["descr"] == "a long description" and r["rows"][0]["name"] == "web" and "NVD" in r["links"]
    assert env["views"].cve("CVE-0000-0000")["rows"] == []
    tok = env["tokens"].mint("t")
    st, body = call(env["url"] + "/api/v1/cve/CVE-2099-0001", headers={"Authorization": "Bearer " + tok})
    assert st == 200 and body["severity"] == "CRITICAL"
    assert "warden_cve" in env["mcp"].BY_NAME


def test_review_20261009_config_and_secret_hardening(env, tmp_path):
    h = {"X-Warden": "config"}
    for bad in ({"key": "ids.suricata_host", "value": "-oProxyCommand=id #@x"},      # reached ssh argv as root
                {"key": "notify.owner_id", "value": "123"},                           # approval authority
                {"key": "cloudflare.zone_id", "value": "../../accounts"},
                {"key": "api.public_url", "value": "javascript:alert(1)"},
                {"key": "notify.ntfy_url", "value": "http://169.254.169.254/x"},
                {"key": "patch.night", "value": "x"}, {"key": "patch.expire_hours", "value": 0},
                {"key": "estate.timezone", "value": "Mars/Base"}, {"key": "estate.name"}):
        assert call(env["url"] + "/api/config", bad, headers=h)[0] == 400, bad
    assert call(env["url"] + "/api/config", {"key": "estate.timezone", "value": "Europe/London"}, headers=h)[0] == 200
    hs = {"X-Warden": "secret"}
    (tmp_path / "secrets.env").write_text("export DISCORD_BOT_TOKEN=old\n")
    assert call(env["url"] + "/api/secret", {"name": "DISCORD_BOT_TOKEN", "value": "a\rOTHER=x"}, headers=hs)[0] == 400
    assert call(env["url"] + "/api/secret", {"name": "DISCORD_BOT_TOKEN", "value": "new"}, headers=hs)[0] == 200
    text = (tmp_path / "secrets.env").read_text()
    assert "old" not in text and "DISCORD_BOT_TOKEN=new" in text and "OTHER" not in text


def test_review_20261009_integrity_never_autoaccepts_persistence():
    import importlib.util
    spec = importlib.util.spec_from_file_location("integrity", ROOT / "integrity.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    for p in ("/root/.ssh/authorized_keys", "/etc/sudoers.d/x", "/etc/cron.d/job", "/etc/ld.so.preload",
              "/etc/pam.d/sshd", "/etc/systemd/system/evil.service", "/etc/shadow"):
        assert m.SENSITIVE.search(p), p
    assert not m.SENSITIVE.search("/usr/bin/curl")


def test_own_ip_left_out_of_counts(env, tmp_path):
    # 10-10: our WAN IP (Uptime Kuma 404s) was 97% of a day's detections and pushed real rows off the lists
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\nui: {auth: proxy}\nallow: [192.0.2.7]\n")
    con = sqlite3.connect(tmp_path / "warden.db")
    con.executemany("insert into events(ts,source,ip,kind,detail,score) values (datetime('now','-10 minutes'),"
                    "'proxy','192.0.2.7','4xx','/',1)", [()] * 150)
    con.commit(); con.close()
    import wlib.config as c
    importlib.reload(c); importlib.reload(env["views"])
    v = env["views"]
    p = v.payload()
    assert p["kpi"]["events_24h"] == 3 and p["kpi"]["events_self_24h"] == 150
    assert all(not r["self"] for r in p["recent"]) and len(p["recent"]) == 3
    assert [r["ip"] for r in p["top"]] == ["203.0.113.9", "198.51.100.4"]
    assert sum(d["n"] for d in p["timeline"]) == 3
    d = v.detections(limit=2)
    assert len(d["rows"]) == 2 and d["self_hidden"] == 150 and all(not r["self"] for r in d["rows"])
    assert len(v.detections(ip="192.0.2.7")["rows"]) == 100        # asked for by IP → shown
    assert all(not r["self"] for r in v.top_ips()["rows"])


def test_console_payload_cache_drops_on_write(env, tmp_path):
    v = env["views"]
    v.invalidate()
    a = v.payload_cached()
    con = sqlite3.connect(tmp_path / "warden.db")
    con.execute("insert into events(ts,source,ip,kind,detail,score) values (datetime('now'),'proxy','203.0.113.50','sqli','x',8)")
    con.commit(); con.close()
    assert v.payload_cached() is a                       # within max_age: same warm copy
    v.invalidate()
    assert v.payload_cached()["kpi"]["events_24h"] == a["kpi"]["events_24h"] + 1
    assert v.payload_cached(max_age=0) is not a
