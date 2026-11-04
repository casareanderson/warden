"""A PyPI fork republished under a new name must still match the original project's advisories (wlib/osv.py,
wlib/imgcollect.py, vulnscan.image_packages). The collector reads the unchanged import name from top_level.txt
and any name declared in Provides-Dist/Obsoletes-Dist, and warden queries OSV for them too, so e.g.
unclecode-litellm (a litellm 1.81 fork) is not invisible. No network."""
import ast
import os as _os
import re as _re

import requests

import vulnscan
from wlib import osv

HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
FORK = ("PyPI", "unclecode-litellm", "1.81.1")


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.headers = status, body, {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class Fake:
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


def test_collector_source_compiles():
    compile(vulnscan.COLLECTOR, "<collector>", "exec")


def _files(name, version, tops):
    return {"IMAGE": b"img:fork",
            "py/1": f"/usr/lib/python3/site-packages/foo.dist-info/METADATA\n{name}\n{version}\n{tops}".encode()}


def _pymeta():
    """The collector's pymeta(), extracted from the self-contained SOURCE string (runs remotely, so it is not
    importable). `head` and `pymeta` are the only functions it needs."""
    tree = ast.parse(vulnscan.COLLECTOR)
    ns = {"os": _os, "re": _re}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("head", "pymeta"):
            exec(compile(ast.Module(body=[node], type_ignores=[]), "<collector>", "exec"), ns)
    return ns["pymeta"]


def test_fork_queries_its_import_name():
    pkgs, _, _, _ = vulnscan.image_packages(_files("unclecode-litellm", "1.81.1", "litellm"))
    assert ("PyPI", "litellm", "1.81.1", "unclecode-litellm", "1.81.1") in pkgs
    assert ("PyPI", "unclecode-litellm", "1.81.1", "unclecode-litellm", "1.81.1") in pkgs


def test_unchanged_name_not_queried_twice():
    pkgs, _, _, _ = vulnscan.image_packages(_files("litellm", "1.81.1", "litellm"))
    assert [p for p in pkgs if p[1] == "litellm"] == [("PyPI", "litellm", "1.81.1", "litellm", "1.81.1")]


def test_no_top_level_still_scans():
    pkgs, _, _, _ = vulnscan.image_packages(_files("unclecode-litellm", "1.81.1", ""))
    assert ("PyPI", "unclecode-litellm", "1.81.1", "unclecode-litellm", "1.81.1") in pkgs
    assert all(p[1] != "litellm" for p in pkgs)


def test_renamed_fork_matches_original_advisory():
    pkgs, _, _, _ = vulnscan.image_packages(_files("unclecode-litellm", "1.81.1", "litellm"))
    lite = {"id": "GHSA-0000-0000-0000", "modified": "m", "summary": "litellm prompt injection",
            "severity": [{"type": "CVSS_V3", "score": HIGH}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "litellm"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.82.0"}]}]}]}
    fake = Fake({FORK: [], ("PyPI", "litellm", "1.81.1"): ["GHSA-0000-0000-0000"]},
                {"GHSA-0000-0000-0000": lite})
    rows = osv.match(osv.OSV(":memory:", session=fake), pkgs, set(), image="img:fork")
    assert [r[0] for r in rows] == ["GHSA-0000-0000-0000"]
    assert rows[0][1] == "unclecode-litellm"       # reported under the installed distribution name
    assert rows[0][3] == "1.82.0"                  # litellm's fix version
    assert rows[0][8] == "img:fork"


def test_collector_folds_provides_dist(tmp_path):
    # a fork that renamed BOTH the dist name and the import module (no top_level.txt) still names the original
    # in Provides-Dist/Obsoletes-Dist, so the collector emits it and warden can match litellm's advisories.
    pymeta = _pymeta()
    meta = (b"Metadata-Version: 2.1\nName: unclecode-litellm\nVersion: 1.81.1\n"
            b"Provides-Dist: litellm (>= 1.81)\nObsoletes-Dist: old-litellm\n\nbody")
    assert pymeta(meta, str(tmp_path)) == b"unclecode-litellm\n1.81.1\nlitellm old-litellm"


def test_provides_dist_name_is_queried(tmp_path):
    pymeta = _pymeta()
    meta = b"Name: unclecode-litellm\nVersion: 1.81.1\nProvides-Dist: litellm (>= 1.81)\n\n"
    files = {"IMAGE": b"img:fork", "py/1": b"METADATA\n" + pymeta(meta, str(tmp_path))}
    pkgs, _, _, _ = vulnscan.image_packages(files)
    assert ("PyPI", "litellm", "1.81.1", "unclecode-litellm", "1.81.1") in pkgs
