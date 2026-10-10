"""Version ordering + parsers for the OSV matcher (wlib/osv.py). Cases come from real misorders found 2026-10-10."""
from wlib import osv


def test_apk_order():
    for a, b, want in [("3.6.7-r10", "3.6.7-r9", 1), ("3.6.7-r0", "3.6.6-r0", 1), ("1.0_rc1-r0", "1.0-r0", -1),
                       ("1.0_p1-r0", "1.0-r0", 1), ("1.2-r0", "1.2.1-r0", -1), ("8.21.0-r0", "8.20.0-r1", 1),
                       ("1.2a-r0", "1.2-r0", 1)]:
        assert osv.apk_cmp(a, b) == want, (a, b)


def test_semver_pep440_order():
    for a, b, want in [("2.0.0rc1", "2.0.0", -1), ("1.0.post1", "1.0", 1), ("v1.2.3", "1.2.10", -1), ("1.0", "1.0.0", 0),
                       ("1.0.0-beta.2", "1.0.0-beta.10", -1), ("1.0.0a1", "1.0.0b1", -1), ("2.0.0.dev1", "2.0.0a1", -1),
                       ("1.0.0-rc.1", "1.0.0", -1), ("1.26.0-rc.3", "1.25.7", 1)]:
        assert osv.gen_cmp(a, b) == want, (a, b)


def test_deb_order():
    assert osv.deb_cmp("1:10.0p1-7+deb13u4", "1:10.0p1-7+deb13u3") == 1
    assert osv.deb_cmp("8.21.0~rc2-1", "8.21.0-1") == -1


def test_fixed_uses_exact_release():
    v = {"affected": [{"package": {"ecosystem": "Debian:13", "name": "curl"}, "ranges": [{"events": []}]},
                      {"package": {"ecosystem": "Debian", "name": "curl"},
                       "ranges": [{"events": [{"fixed": "8.21.0~rc2-1"}]}]}]}
    assert osv._fixed(v, "Debian:13", "curl", "8.14.1-2+deb13u5") == ""


def test_dpkg_source_mapping():
    st = "Package: libcurl4t64\nStatus: install ok installed\nSource: curl (8.14.1-2)\nVersion: 8.14.1-2+b1\n\n"
    assert osv.parse_dpkg(st) == [("curl", "8.14.1-2", "libcurl4t64", "8.14.1-2+b1")]


def test_cvss3():
    assert osv.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.level(osv.cvss3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N")) == "LOW"
