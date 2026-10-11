"""incidents.py (shadow): correlation across detectors, the decision validator, the shadow guarantees, agreement stats."""
import importlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def ts(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture()
def inc(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(
        "estate: {name: test, lan: [10.0.0.0/24]}\nnotify: {backend: none}\nallow: [198.51.100.7]\n"
        "incidents: {mode: shadow, gap_hours: 24, min_weight: 1, max_decisions: 5,\n"
        "  model: {url: https://example.invalid/v1, models: [test/model]}}\n")
    import wlib.config as c
    importlib.reload(c)
    import wlib.secrets, wlib.views  # noqa: E401
    for m in (wlib.secrets, wlib.views):
        importlib.reload(m)
    import incidents
    importlib.reload(incidents)
    con = sqlite3.connect(c.DB)
    con.executescript("""
      begin;
      create table events(id integer primary key, ts text, source text, ip text, kind text, detail text, score integer);
      create table edge_events(id integer primary key, ts text, ray text, ip text, cc text, action text, source text,
        host text, path text, ua text, rule text);
      create table ids_alerts(id integer primary key, ts text, sid integer, signature text, severity integer, category text,
        src text, sport integer, dst text, dport integer, proto text, app text, cc text, community_id text, notified integer);
      create table intel_hits(id integer primary key, ts text, device text, device_name text, kind text, indicator text,
        feed text, detail text, notified integer);
      create table integ_find(id integer primary key, ts text, target text, kind text, item text, old text, new text,
        change text, status text, message_id text, note text);
      create table logins(id integer primary key, target text, ts text, user text, src text, method text, key_fp text,
        ok integer, self integer default 0, new integer default 0);
      create table hb_events(id integer primary key, ts text, target text, event text, detail text);
      create table edge_bans(id integer primary key, target text, reason text, score integer, status text, message_id text,
        created text, decided text, expires text, note text);
      create table bans(id integer primary key, ts text, ip text, score integer, reasons text, state text, expires text, note text);
      create table devices(mac text primary key, ip text, name text, identity text);
      commit;
    """)
    con.commit()
    incidents.test_con = con
    return incidents


def seed(con):
    con.executemany("insert into events(ts, source, ip, kind, detail, score) values(?,?,?,?,?,?)", [
        (ts(hours=5), "npm", "203.0.113.9", "sensitive-file", "/.env", 8),
        (ts(hours=4), "npm", "203.0.113.41", "traversal", "/../../etc/passwd", 8),    # same /24 as .9
        (ts(hours=3), "npm", "198.51.100.7", "4xx", "own address", 1),                # ours (allow) → dropped
        (ts(days=3), "npm", "192.0.2.5", "4xx", "/favicon2.ico", 1),                   # lone 404 elsewhere
    ])
    con.execute("insert into edge_events(ts, ray, ip, cc, action, host, path, rule) values(?,?,?,?,?,?,?,?)",
                (ts(hours=4), "r1", "203.0.113.9", "NL", "block", "auth.example.com", "/.git/HEAD", "block .git"))
    con.execute("insert into edge_events(ts, ray, ip, cc, action) values(?,?,?,?,?)",
                (ts(hours=4), "r2", "203.0.113.9", "NL", "log"))                       # informational → dropped
    con.execute("insert into logins(target, ts, user, src, method, ok, self, new) values(?,?,?,?,?,?,?,?)",
                ("host:10.0.0.5", ts(hours=2), "admin", "203.0.113.77", "password", 0, 0, 0))
    con.execute("insert into logins(target, ts, user, src, method, ok, self, new) values(?,?,?,?,?,?,?,?)",
                ("host:10.0.0.5", ts(hours=1), "root", "10.0.0.40", "publickey", 1, 1, 0))    # warden's own → dropped
    con.execute("insert into integ_find(ts, target, kind, item, change, status, note) values(?,?,?,?,?,?,?)",
                (ts(hours=1), "host:10.0.0.5", "file", "/etc/ssh/sshd_config", "changed", "accepted", "owner ✅ — new baseline"))
    con.execute("insert into hb_events(ts, target, event, detail) values(?,?,?,?)", (ts(hours=6), "ct:101", "down", "timeout"))
    con.commit()


def test_correlation_joins_a_slash24_and_links_box_and_address(inc):
    con = inc.db()
    seed(inc.test_con)
    added = inc.correlate(con)
    ents = {r["entity"]: r for r in con.execute("select * from incidents")}
    assert "net:203.0.113.0/24" in ents
    big = ents["net:203.0.113.0/24"]
    # two log events from two addresses in one /24, one STOPPED edge event (the 'log' one is not), one failed sign-in
    facts = {r[0] for r in con.execute("select fact_id from incident_facts where incident_id=?", (big["id"],))}
    assert {"edge:r1"} <= facts and "edge:r2" not in facts
    assert sum(1 for f in facts if f.startswith("ev:")) == 2 and any(f.startswith("login:") for f in facts)
    assert not any("198.51.100" in e for e in ents)                     # own address never becomes an incident
    assert ents["box:host:10.0.0.5"]["n_facts"] == 2                    # failed sign-in + integrity change
    f = inc.facts_for(con, ents["box:host:10.0.0.5"]["id"])
    assert "net:203.0.113.0/24" in f["related_incidents"]               # the sign-in links box and address
    assert added == sum(r["n_facts"] for r in ents.values())
    assert inc.correlate(con) == 0                                       # re-run over the overlap adds nothing


def test_outbound_ids_alert_is_about_the_device_not_the_address(inc):
    con = inc.db()
    inc.test_con.execute("insert into devices(mac, ip, name, identity) values('aa:00:00:00:00:01', '10.0.0.31', 'tv', 'mac:aa')")
    inc.test_con.executemany("insert into ids_alerts(ts, signature, severity, src, dst, dport) values(?,?,?,?,?,?)", [
        (ts(hours=2), "ET POLICY outbound", 2, "10.0.0.31", "203.0.113.50", 443),      # LAN device → outside
        (ts(hours=1), "ET SCAN inbound", 2, "198.18.0.9", "10.0.0.5", 22),             # outside → LAN
        (ts(hours=1), "SURICATA Applayer Detect protocol only one direction", 3, "192.0.2.80", "10.0.0.31", 443)])
    inc.test_con.commit()
    inc.correlate(con)
    ents = {r[0] for r in con.execute("select entity from incidents")}
    assert "device:mac:aa" in ents and "net:203.0.113.0/24" not in ents and "net:198.18.0.0/24" in ents
    assert "net:192.0.2.0/24" not in ents                               # decoder noise never becomes an incident


def test_gap_opens_a_new_incident(inc):
    con = inc.db()
    inc.test_con.executemany("insert into events(ts, source, ip, kind, detail, score) values(?,?,?,?,?,?)", [
        (ts(days=5), "npm", "192.0.2.10", "sqli", "x", 8), (ts(days=1), "npm", "192.0.2.11", "sqli", "y", 8)])
    inc.test_con.commit()
    inc.correlate(con)
    assert con.execute("select count(*) from incidents where entity='net:192.0.2.0/24'").fetchone()[0] == 2


def facts_fixture():
    return {"incident": "net:203.0.113.0/24", "signals": 3, "by_source": {"npm": 2, "cloudflare": 1},
            "facts": [{"id": "ev:1", "what": "sensitive-file from 203.0.113.9: /.env", "ip": "203.0.113.9"},
                      {"id": "edge:r1", "what": "edge block 203.0.113.9 (NL) auth.example.com/.git/HEAD"},
                      {"id": "ev:2", "what": "traversal from 203.0.113.41"}]}


@pytest.mark.parametrize("d,ok", [
    ({"action": "propose_edge_block", "confidence": 0.8, "why": "Two addresses in this /24 probed /.env and traversal, "
      "and the edge already blocked 203.0.113.9.", "cited": ["ev:1", "ev:2", "edge:r1"]}, True),
    ({"action": "propose_edge_block", "confidence": 0.8, "why": "It made 57 attempts.", "cited": ["ev:1"]}, False),
    ({"action": "propose_edge_block", "confidence": 0.8, "why": "Blocked at the edge.", "cited": ["ev:9"]}, False),
    ({"action": "ban_forever", "confidence": 0.8, "why": "Hostile.", "cited": ["ev:1"]}, False),
    ({"action": "watch", "confidence": 1.4, "why": "Unclear.", "cited": ["ev:1"]}, False),
    ({"action": "watch", "confidence": 0.5, "why": "It also hit evil.example.net.", "cited": ["ev:1"]}, False),
    ({"action": "watch", "confidence": 0.5, "why": "Looks like CVE-2024-3094.", "cited": ["ev:1"]}, False),
    ({"action": "watch", "confidence": 0.5, "why": "Scanner noise.", "cited": []}, False),
])
def test_validator(inc, d, ok):
    assert (inc.check(d, facts_fixture()) == "") is ok


def test_shadow_decides_withholds_and_never_acts(inc, monkeypatch):
    con = inc.db()
    seed(inc.test_con)
    inc.correlate(con)
    answers = iter([
        # heaviest first: the /24 gets a good answer; the box gets a made-up number, then a broken repair → withheld
        json.dumps({"action": "propose_edge_block", "confidence": 0.7, "why": "Probed /.env from 203.0.113.9.",
                    "cited": ["ev:1"]}),
        json.dumps({"action": "check_box", "confidence": 0.6, "why": "Someone tried 99 passwords.", "cited": ["login:1"]}),
        json.dumps({"action": "nonsense"}),
    ])
    posts = []

    class R:
        def __init__(self, text):
            self.text = text

        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": self.text}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20, "cost": 0.0001}}

    def post(url, **kw):
        posts.append(kw["json"])
        assert kw["json"]["reasoning"] == {"enabled": False}
        return R(next(answers, json.dumps({"action": "watch", "confidence": 0.5, "why": "Quiet.", "cited": []})))
    monkeypatch.setattr(inc.requests, "post", post)
    before = {t: inc.test_con.execute(f"select count(*) from {t}").fetchone()[0] for t in ("bans", "edge_bans")}
    done = inc.decide(con)
    assert done["decided"] >= 1 and done["withheld"] >= 1
    rows = {r["status"] for r in con.execute("select status from incident_decisions")}
    assert rows == {"ok", "withheld"}
    after = {t: inc.test_con.execute(f"select count(*) from {t}").fetchone()[0] for t in ("bans", "edge_bans")}
    assert before == after                                              # never writes ban or edge-ban rows
    assert not inc.test_con.execute("select 1 from sqlite_master where name='patch_jobs'").fetchone()
    assert "notify" not in vars(inc)                                    # can't send: notify is not even imported
    n = con.execute("select count(*) from incident_decisions").fetchone()[0]
    inc.decide(con)
    assert con.execute("select count(*) from incident_decisions").fetchone()[0] == n


def test_no_model_configured_means_correlation_only(inc, monkeypatch):
    monkeypatch.setattr(inc, "model_cfg", lambda: None)
    monkeypatch.setattr(inc.requests, "post", lambda *a, **k: pytest.fail("must not call a model"))
    con = inc.db()
    seed(inc.test_con)
    inc.correlate(con)
    assert inc.decide(con) == {"decided": 0, "withheld": 0}


def test_owner_labels_and_agreement(inc, monkeypatch):
    con = inc.db()
    seed(inc.test_con)
    inc.test_con.execute("insert into edge_bans(target, status) values('203.0.113.0/24', 'active')")
    inc.test_con.commit()
    inc.correlate(con)
    assert inc.label(con) == 2                                          # /24 → act (approved ban); box → benign (✅)
    lab = dict(con.execute("select entity, owner_label from incidents where owner_label is not null").fetchall())
    assert lab == {"net:203.0.113.0/24": "act", "box:host:10.0.0.5": "benign"}
    ids = dict(con.execute("select entity, id from incidents").fetchall())
    for ent, action in (("net:203.0.113.0/24", "propose_edge_block"), ("box:host:10.0.0.5", "check_box")):
        con.execute("insert into incident_decisions(incident_id, ts, status, action, confidence, cost) values(?,?,?,?,?,?)",
                    (ids[ent], ts(), "ok", action, 0.7, 0.0002))
    con.commit()
    r = inc.report(con)
    assert (r["agree"], r["disagree"]) == (1, 1) and r["decided"] == 2 and r["cost_usd"] == 0.0004
