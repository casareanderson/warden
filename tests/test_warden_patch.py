"""Offline tests for warden-patch: the plan renderer and the refuse-on-remove guard (no SSH)."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader("warden_patch", str(ROOT / "warden-patch"))
    spec = importlib.util.spec_from_loader("warden_patch", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_render_shows_upgrades_and_removals():
    p = _load()
    out = p.render("root@box", [("curl", "7.8", "7.9"), ("bash", "5.2", "5.3")], ["old-lib"])
    assert "2 to install/upgrade" in out and "old-lib" in out and "upgrade: curl" in out


def test_render_refuses_critical_removals():
    p = _load()
    out = p.render("root@box", [], ["systemd", "libc6"])
    assert "REFUSED" in out and "systemd" in out


def test_render_nothing_to_do():
    p = _load()
    assert "already up to date" in p.render("root@box", [], [])
