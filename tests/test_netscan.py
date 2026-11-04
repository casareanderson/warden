"""netscan OUI lookup: fresh when it can be, but never guessed.

nmap's shipped vendor table is a snapshot (the packaged one is dated April
2024) and misses newer allocations — one prefix here accounts for 17 hosts.
`_load_oui()` now refreshes a copy from nmap's own repo before falling back to
the shipped file, and `OUI_EXTRA` patches only *verifiable* gaps: a guessed
vendor name is worse than a blank one, because it makes an unknown device look
identified. These tests pin that contract.
"""
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import netscan  # noqa: E402


# Words that would betray a guessed (rather than verified) vendor assignment.
GUESS_MARKERS = ("guess", "probably", "maybe", "perhaps", "likely", "possibly",
                 "unknown", "unidentified", "unverified", "unclear", "?")


def _fake_table(monkeypatch, tmp_path, *lines):
    tbl = tmp_path / "nmap-mac-prefixes"
    tbl.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(netscan, "OUI_FILE", str(tbl))
    monkeypatch.setattr(netscan, "OUI_CACHE", tmp_path / "cache-mac-prefixes")
    monkeypatch.setattr(netscan, "refresh_oui", lambda: False)
    monkeypatch.setattr(netscan, "_oui", None)


class _Response:
    def __init__(self, text):
        self._text = text

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._text.encode()


def _big_table(extra="", n=1000):
    return "\n".join(f"{i:06X} Vendor{i}" for i in range(n)) + "\n" + extra


def test_vendor_comes_from_table(monkeypatch, tmp_path):
    _fake_table(monkeypatch, tmp_path, "A043B0 Hangzhou BroadLink")
    assert netscan.vendor_of("a0:43:b0:11:22:33") == "Hangzhou BroadLink"


def test_oui_extra_wins_over_table(monkeypatch, tmp_path):
    _fake_table(monkeypatch, tmp_path, "BC2411 Some Other Vendor")
    assert netscan.vendor_of("bc:24:11:aa:bb:cc") == "Proxmox VE (virtual NIC)"


def test_unknown_prefix_is_flagged_not_guessed(monkeypatch, tmp_path):
    _fake_table(monkeypatch, tmp_path)  # empty table
    # 00:00:00 has the locally-administered bit clear, so it is not routed to
    # the "randomised MAC" answer — it is a genuinely unknown prefix.
    out = netscan.vendor_of("00:00:00:aa:bb:cc")
    assert out == "unknown (OUI 00:00:00 not in table)"


def test_random_mac_is_flagged(monkeypatch, tmp_path):
    _fake_table(monkeypatch, tmp_path)
    assert "randomised" in netscan.vendor_of("02:00:00:aa:bb:cc")


def test_oui_extra_entries_are_verifiable():
    for pre, name in netscan.OUI_EXTRA.items():
        assert len(pre) == 6 and all(c in "0123456789ABCDEF" for c in pre), \
            f"OUI_EXTRA key {pre!r} is not a 6-digit uppercase hex prefix"
        assert name and name.strip() == name, \
            f"OUI_EXTRA value for {pre!r} is empty or untrimmed: {name!r}"
        low = name.lower()
        assert not any(m in low for m in GUESS_MARKERS), \
            f"OUI_EXTRA entry {pre!r} looks like a guess, not a verified vendor: {name!r}"


def test_refresh_oui_caches_fresh_table(monkeypatch, tmp_path):
    monkeypatch.setattr(netscan, "OUI_FILE", str(tmp_path / "nmap-mac-prefixes"))
    monkeypatch.setattr(netscan, "OUI_CACHE", tmp_path / "cache-mac-prefixes")
    monkeypatch.setattr(netscan, "_oui", None)
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda req, timeout=None: _Response(_big_table("AABBCC AcmeFreshCorp\n")))

    assert netscan.refresh_oui() is True
    assert netscan.vendor_of("aa:bb:cc:11:22:33") == "AcmeFreshCorp"


def test_refresh_oui_refuses_truncated_download(monkeypatch, tmp_path):
    cache = tmp_path / "cache-mac-prefixes"
    cache.write_text(_big_table("AABBCC KeepMe\n"))
    monkeypatch.setattr(netscan, "OUI_FILE", str(tmp_path / "nmap-mac-prefixes"))
    monkeypatch.setattr(netscan, "OUI_CACHE", cache)
    monkeypatch.setattr(netscan, "_oui", None)
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda req, timeout=None: _Response("AABBCC Sneaky\n"))  # far too small

    assert netscan.refresh_oui() is False
    assert netscan.vendor_of("aa:bb:cc:11:22:33") == "KeepMe"


def test_refresh_oui_offline_falls_back_to_shipped(monkeypatch, tmp_path):
    shipped = tmp_path / "nmap-mac-prefixes"
    shipped.write_text("A043B0 Hangzhou BroadLink\n")
    monkeypatch.setattr(netscan, "OUI_FILE", str(shipped))
    monkeypatch.setattr(netscan, "OUI_CACHE", tmp_path / "cache-mac-prefixes")
    monkeypatch.setattr(netscan, "_oui", None)

    def boom(req, timeout=None):
        raise OSError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert netscan.refresh_oui() is False
    assert netscan.vendor_of("a0:43:b0:11:22:33") == "Hangzhou BroadLink"
