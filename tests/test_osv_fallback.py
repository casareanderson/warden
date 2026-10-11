"""OSV.dev outage fallback (wlib/osv.py): when the querybatch endpoint is unreachable, a scan must keep
reporting from cached advisory bodies (marked stale) instead of erroring per target. No network here."""
import requests

from wlib import osv

HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
PKG = ("Debian:11", "policykit-1", "0.105-31", "libpolkit-gobject-1-0", "0.105-31")
CVE = {"id": "DEBIAN-CVE-2021-4034", "modified": "m", "summary": "policykit-1 privilege escalation",
       "severity": [{"type": "CVSS_V3", "score": HIGH}],
       "affected": [{"package": {"ecosystem": "Debian:11", "name": "policykit-1"},
                     "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.105-31+deb11u1"}]}]}]}


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.headers = status, body, {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class Fake:
    """requests.Session stand-in: querybatch answers by (ecosystem, name, version), /vulns/<id> by id."""

    def __init__(self, hits, vulns):
        self.headers, self.hits, self.vulns = {}, hits, vulns

    def post(self, url, json=None, timeout=None):
        return Resp(200, {"results": [{"vulns": [{"id": i, "modified": self.vulns.get(i, {}).get("modified", "m")}
                                                  for i in self.hits.get((q["package"]["ecosystem"],
                                                                          q["package"]["name"], q["version"]), [])]}
                                      for q in json["queries"]]})

    def get(self, url, timeout=None, headers=None):
        vid = url.rsplit("/", 1)[1]
        return Resp(200, self.vulns[vid]) if vid in self.vulns else Resp(404, {})


class Down:
    """OSV unreachable: every request fails as a connection error."""

    def post(self, url, json=None, timeout=None):
        raise requests.ConnectionError("offline")

    def get(self, url, timeout=None, headers=None):
        raise requests.ConnectionError("offline")


def test_query_falls_back_to_cached_advisories(tmp_path, monkeypatch):
    monkeypatch.setattr(osv.OSV, "_wait", staticmethod(lambda r, a: None))
    db = str(tmp_path / "warden.db")
    c = osv.OSV(db, session=Fake({PKG[:3]: ["DEBIAN-CVE-2021-4034"]}, {"DEBIAN-CVE-2021-4034": CVE}))
    want = osv.match(c, [PKG], set(), image="x")
    assert [r[0] for r in want] == ["CVE-2021-4034"] and want[0][3] == "0.105-31+deb11u1"

    c.s = Down()
    assert c.degraded == 0
    got = osv.match(c, [PKG], set(), image="x")
    assert c.degraded == 1                       # the outage was recorded, not an exception
    assert got == want                           # same rows, served from the cached advisory body
