"""devices.py: classification and grouping, from the real mix on the owner's network (2026-10-10)."""
import importlib, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path)); monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "w.yml"))
    (tmp_path / "w.yml").write_text("hosts:\n  - {name: nas, ssh: root@192.0.2.10}\n")
    import wlib.config as c; importlib.reload(c)
    import devices; importlib.reload(devices)
    return devices


def test_kinds(tmp_path, monkeypatch):
    D = load(tmp_path, monkeypatch)
    k = lambda host="", vendor="", ha=None, ip="": D.classify(ha or {}, host, vendor, ip, D.declared_ips())[0]
    assert k(vendor="WiZ IoT Company Limited") == "bulb"
    assert k(host="AppleTV-LivingRoom") == "tv" and k(host="LGwebOSTV") == "tv"
    assert k(host="TL-SG108E") == "network" and k(host="eero") == "network"
    assert k(host="garden-bt-proxy") == "iot" and k(host="AugustConnect") == "iot"
    assert k(host="S380HB") == "camera" and k(host="Klipper.lan") == "printer"
    assert k(ip="192.0.2.10", host="anything") == "server"                 # declared in warden.yml
    assert k(ha={"domains": ["media_player"], "maker": "Sonos", "model": "One"}) == "speaker"
    assert k(ha={"domains": ["media_player"], "maker": "LG", "model": "webOS TV OLED55"}) == "tv"
    assert k(ha={"domains": ["switch"], "maker": "Espressif", "model": "ESP32"}, host="esp32-x") == "iot"   # a switch ≠ a plug
    assert k(host="15AA01AC511808MK") == "unknown"                          # honest unknown, not a guess


def test_private_addresses_group_by_name_but_not_generic_names(tmp_path, monkeypatch):
    D = load(tmp_path, monkeypatch)
    assert D.identity("da:11:22:33:44:55", "laptop-7.lan", "") == D.identity("6e:aa:bb:cc:dd:ee", "laptop-7", "") == "host:laptop-7"
    assert D.identity("da:11:22:33:44:55", "iPhone", "") != D.identity("6e:aa:bb:cc:dd:ee", "iPhone", "")
    assert D.identity("a0:43:b0:00:00:01", "BL-01", "Hangzhou BroadLink") == "mac:a0:43:b0:00:00:01"   # real MAC: itself
