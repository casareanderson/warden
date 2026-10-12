"""`ui.auth: proxy` trusts the Remote-User header, so warden must refuse a routable bind (where anyone could
forge it) unless the operator opts in. Regression for the 2026-10 review finding (confirmed exploitable)."""
import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(tmp_path, monkeypatch, yml):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text(yml)
    import wlib.config as c
    importlib.reload(c)
    import wlib.auth
    importlib.reload(wlib.auth)
    spec = importlib.util.spec_from_file_location("warden_ui", ROOT / "warden-ui.py")
    ui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ui)
    return ui


def test_proxy_refuses_routable_bind(tmp_path, monkeypatch):
    ui = _load(tmp_path, monkeypatch, "estate: {name: t}\nnotify: {backend: none}\nui: {auth: proxy, host: 0.0.0.0}\n")
    for host in ("0.0.0.0", "10.0.0.5", "::", "192.0.2.9"):
        with pytest.raises(SystemExit):
            ui._guard_proxy_bind(host)


def test_proxy_loopback_ok(tmp_path, monkeypatch):
    ui = _load(tmp_path, monkeypatch, "estate: {name: t}\nnotify: {backend: none}\nui: {auth: proxy, host: 127.0.0.1}\n")
    ui._guard_proxy_bind("127.0.0.1")
    ui._guard_proxy_bind("localhost")
    ui._guard_proxy_bind("::1")


def test_proxy_optin_allows_routable(tmp_path, monkeypatch):
    ui = _load(tmp_path, monkeypatch,
               "estate: {name: t}\nnotify: {backend: none}\nui: {auth: proxy, host: 0.0.0.0, trust_proxy_insecure: true}\n")
    ui._guard_proxy_bind("0.0.0.0")


def test_local_mode_unaffected(tmp_path, monkeypatch):
    ui = _load(tmp_path, monkeypatch, "estate: {name: t}\nnotify: {backend: none}\nui: {host: 0.0.0.0}\n")
    ui._guard_proxy_bind("0.0.0.0")
