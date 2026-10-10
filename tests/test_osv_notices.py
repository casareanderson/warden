"""Debian 10/11 DSA/DLA notice expansion + advisory cache schema (wlib/osv.py), against a stubbed OSV: no network.
On 2026-10-10 OSV had no per-CVE records for buster/bullseye, only notices, so skipping notices hid PwnKit."""
import json
import sqlite3

from wlib import osv

HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
PKG = ("Debian:11", "policykit-1", "0.105-31", "libpolkit-gobject-1-0", "0.105-31")


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.headers = status, body, {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


class Fake:
    """requests.Session stand-in: querybatch answers by (ecosystem, name, version), /vulns/<id> by id."""

    def __init__(self, hits, vulns):
        self.headers, self.hits, self.vulns, self.gets = {}, hits, vulns, []

    def post(self, url, json=None, timeout=None):
        return Resp(200, {"results": [{"vulns": [{"id": i, "modified": self.vulns.get(i, {}).get("modified", "m")}
                                                  for i in self.hits.get((q["package"]["ecosystem"],
                                                                          q["package"]["name"], q["version"]), [])]}
                                      for q in json["queries"]]})

    def get(self, url, timeout=None, headers=None):
        self.gets.append(url)
        vid = url.rsplit("/", 1)[1]
        return Resp(200, self.vulns[vid]) if vid in self.vulns else Resp(404, {})


def dsa(*cves):
    return {"id": "DSA-5059-1", "modified": "m", "summary": "policykit-1 - security update",
            "upstream": list(cves),
            "affected": [{"package": {"ecosystem": "Debian:11", "name": "policykit-1"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.105-31+deb11u1"}]}]}]}


def rows(vulns, hits, kev=()):
    out = osv.match(osv.OSV(":memory:", session=Fake(hits, vulns)), [PKG], set(kev), image="img:bullseye")
    for r in out:
        assert len(r) == 11                     # vulnscan row tuple shape is unchanged
    return out


def test_notice_only_cve_is_reported():
    v = {"DSA-5059-1": dsa("CVE-2021-4034", "DEBIAN-CVE-2021-4034"),
         "CVE-2021-4034": {"id": "CVE-2021-4034", "modified": "m", "summary": "pkexec local privilege escalation",
                           "severity": [{"type": "CVSS_V3", "score": HIGH}]}}
    out = rows(v, {PKG[:3]: ["DSA-5059-1"]}, kev={"CVE-2021-4034"})
    assert len(out) == 1
    vid, pkg, inst, fixed, sev, title, kev, status, image, descr, url = out[0]
    assert (vid, pkg, inst) == ("CVE-2021-4034", "libpolkit-gobject-1-0", "0.105-31")
    assert fixed == "0.105-31+deb11u1" and status == "fixed"
    assert sev == "HIGH"                        # borrowed from the CVE record
    assert kev == 1 and image == "img:bullseye"
    assert title == "pkexec local privilege escalation"
    assert url == "https://osv.dev/vulnerability/DSA-5059-1"


def test_notice_and_per_cve_record_reported_once():
    v = {"DSA-5059-1": dsa("CVE-2021-4034", "CVE-2025-0009"),
         "DEBIAN-CVE-2025-0009": {"id": "DEBIAN-CVE-2025-0009", "modified": "m", "summary": "per-cve",
                                  "affected": [{"package": {"ecosystem": "Debian:11", "name": "policykit-1"},
                                                "ranges": [{"events": [{"fixed": "0.105-31+deb11u2"}]}]}]}}
    out = rows(v, {PKG[:3]: ["DSA-5059-1", "DEBIAN-CVE-2025-0009"]})
    by = {}
    for r in out:
        by.setdefault(r[0], []).append(r)
    assert set(by) == {"CVE-2021-4034", "CVE-2025-0009"}
    assert all(len(x) == 1 for x in by.values())
    assert by["CVE-2025-0009"][0][3] == "0.105-31+deb11u2"     # the per-CVE record wins over the notice
    assert by["CVE-2025-0009"][0][5] == "per-cve"


def test_withdrawn_notice_ignored():
    v = {"DSA-5059-1": dict(dsa("CVE-2021-4034"), withdrawn="2025-01-01")}
    assert rows(v, {PKG[:3]: ["DSA-5059-1"]}) == []


def test_slim_keeps_notice_cves():
    b = osv.slim({"id": "DLA-1-1", "upstream": ["CVE-2021-3156", "DEBIAN-CVE-2021-3156"], "aliases": []})
    assert b["upstream"] == ["CVE-2021-3156"] and osv._notice_cves(b) == ["CVE-2021-3156"]


def test_old_cache_invalidated_and_refetched(tmp_path):
    """A warden DB from before CACHE_SCHEMA: old notice bodies lack `upstream`, so they must be refetched.
    Other warden tables in the same DB are left alone."""
    db = str(tmp_path / "warden.db")
    con = sqlite3.connect(db)
    con.execute("create table osv_vulns(id text primary key, modified text, body text, fetched text)")
    old = {"id": "DSA-5059-1", "modified": "m", "affected": dsa()["affected"]}         # pre-change slim(): no upstream
    con.execute("insert into osv_vulns values('DSA-5059-1','m',?,'2026-10-09 00:00:00')", (json.dumps(old),))
    con.execute("create table vulns(vid text)")
    con.execute("insert into vulns values('CVE-1')")
    con.commit()
    con.close()

    s = Fake({PKG[:3]: ["DSA-5059-1"]}, {"DSA-5059-1": dsa("CVE-2021-4034")})
    c = osv.OSV(db, session=s)
    assert c.con.execute("select count(*) from osv_vulns").fetchone()[0] == 0
    assert c.con.execute("select v from osv_meta where k='cache_schema'").fetchone()[0] == str(osv.CACHE_SCHEMA)
    assert c.con.execute("select count(*) from vulns").fetchone()[0] == 1
    out = osv.match(c, [PKG], set(), image="h")
    assert [r[0] for r in out] == ["CVE-2021-4034"]
    assert any(u.endswith("/vulns/DSA-5059-1") for u in s.gets)

    # reopening at the current schema keeps the cache: a repeat scan downloads nothing
    c.con.close()
    s2 = Fake({PKG[:3]: ["DSA-5059-1"]}, {})
    c2 = osv.OSV(db, session=s2)
    assert c2.con.execute("select count(*) from osv_vulns where id='DSA-5059-1'").fetchone()[0] == 1
    assert [r[0] for r in osv.match(c2, [PKG], set(), image="h")] == ["CVE-2021-4034"]
    assert not any(u.endswith("/vulns/DSA-5059-1") for u in s2.gets)
