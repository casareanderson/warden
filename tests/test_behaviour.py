"""wlib/behaviour.py: per-device DNS baselines (step 2)."""
import importlib, sqlite3, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from wlib import behaviour as B  # noqa: E402


def test_registrable():
    assert B.registrable("eu-iot-03.wiz.com.") == "wiz.com"
    assert B.registrable("www.bbc.co.uk") == "bbc.co.uk"
    assert B.registrable("x.y.s3.amazonaws.com") == "s3.amazonaws.com"
    for junk in ("wlan0.lan", "printer.local", "4.3.2.1.in-addr.arpa", "_googlecast._tcp.local", "localhost", "192.0.2.1", ""):
        assert B.registrable(junk) is None


def test_record_counts_days_and_groups_devices(tmp_path):
    con = sqlite3.connect(tmp_path / "w.db")
    con.execute("create table devices(ip text, identity text, last_seen text)")
    con.executemany("insert into devices values(?,?,?)", [("192.0.2.50", "host:laptop-7", "a"), ("192.0.2.51", "host:laptop-7", "b"),
                                                           ("192.0.2.60", "mac:a0:43:b0:00:00:01", "c")])
    q = lambda ip, h: {"IP": ip, "QH": h}
    nd, nn = B.record(con, [q("192.0.2.50", "api.github.com"), q("192.0.2.51", "github.com"),   # one laptop, two addresses
                            q("192.0.2.60", "eu-iot-03.wiz.com"), q("192.0.2.60", "x.lan"), q("10.9.9.9", "a.example.org")],
                      ts="2026-10-10 10:00:00")
    assert (nd, nn) == (3, 3)
    assert con.execute("select hits, days from dev_dns where identity='host:laptop-7' and domain='github.com'").fetchone() == (2, 1)
    B.record(con, [q("192.0.2.60", "eu-iot-03.wiz.com")], ts="2026-10-10 11:00:00")       # same day: days stays 1
    B.record(con, [q("192.0.2.60", "eu-iot-03.wiz.com")], ts="2026-10-11 09:00:00")       # next day: days 2
    assert con.execute("select hits, days from dev_dns where domain='wiz.com'").fetchone() == (3, 2)
    assert con.execute("select count(*) from dev_dns where identity='ip:10.9.9.9'").fetchone()[0] == 1   # unknown ip kept
    assert B.learning(con, "host:laptop-7")
    p = B.profile(con, "mac:a0:43:b0:00:00:01")
    assert p["domains"][0]["domain"] == "wiz.com" and p["learning"]


def test_devicewatch_scoring():
    import devicewatch as D
    base = {"device": "bulb-1", "kind": "bulb", "room": "", "domain": "x.xyz", "first_seen_local": "", "hour": 3,
            "other_devices_using_it": 0, "same_kind_same_day": 0, "usual_domains": ["wiz.world"], "tld": "xyz",
            "maker_in_domain": False}
    s, why = D.score(base)
    assert s == 95 and D.decision(s) == "review"
    fleet = dict(base, hour=14, tld="world", same_kind_same_day=5, maker_in_domain=True, other_devices_using_it=5)
    assert D.decision(D.score(fleet)[0]) == "learned"          # five bulbs got a WiZ domain the same day: firmware
    assert D.decision(D.score(dict(base, hour=14, tld="com"))[0]) == "review"   # lone new .com at 2pm still asks
