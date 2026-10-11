"""Optional Beszel host-health card: snapshot + API sources, ignore rules, and the one-time auto widget."""
import importlib
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture()
def load(tmp_path, monkeypatch):
    def _load(beszel_yaml, env=None):
        monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
        monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)
        (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\n" + beszel_yaml)
        import wlib.config as c
        importlib.reload(c)
        import wlib.secrets, wlib.hosthealth, wlib.views  # noqa: E401
        for m in (wlib.secrets, wlib.hosthealth, wlib.views):
            importlib.reload(m)
        return wlib.hosthealth, wlib.views
    return _load


def snapshot(path, age_s=10, hosts=None):
    now = datetime.now(timezone.utc)
    path.write_text(json.dumps({"generated": iso(now - timedelta(seconds=age_s)), "hosts": hosts or [
        {"name": "nas", "status": "up", "stale": False, "alerts": ["Disk"], "disk_pct": 100, "last_seen": iso(now)},
        {"name": "web", "status": "up", "stale": False, "alerts": ["CPU"], "cpu": 93.2, "last_seen": iso(now)},
        {"name": "db", "status": "up", "stale": False, "alerts": [], "cpu": 4, "last_seen": iso(now)},
        {"name": "old", "status": "down", "stale": True, "alerts": [], "last_seen": "2026-07-19T19:47:20Z"},
        {"name": "ghost", "status": "down", "stale": True, "alerts": []}]}))


def test_off_by_default(load):
    hh, views = load("")
    assert hh.fetch() is None and views.auto_widgets() == ["map"]
    assert "hosthealth" not in views.layout()["widgets"]


def test_snapshot_source_with_ignores(load, tmp_path):
    snapshot(tmp_path / "hosts.json")
    hh, _ = load(f"beszel: {{enabled: true, snapshot: {tmp_path / 'hosts.json'}, link: 'http://hub:8090',"
                 " ignore_hosts: [ghost], ignore_alerts: {nas: [Disk]}}\n")
    r = hh.fetch()
    assert [h["name"] for h in r["hosts"]] == ["old", "web", "db", "nas"]       # not reporting, then hot, then ok
    assert r["summary"] == {"total": 4, "ok": 2, "hot": 1, "stale": 1, "attention": ["old: not reporting", "web: CPU"]}
    assert r["hidden"] == ["ghost"] and r["link"] == "http://hub:8090"


def test_stale_snapshot_is_an_error_not_a_crash(load, tmp_path):
    snapshot(tmp_path / "hosts.json", age_s=3600)
    hh, _ = load(f"beszel: {{enabled: true, snapshot: {tmp_path / 'hosts.json'}}}\n")
    r = hh.fetch()
    assert "snapshot is" in r["error"] and r["hosts"] == [] and r["summary"] is None


class FakeBeszel(BaseHTTPRequestHandler):
    """Just enough PocketBase: password auth, then token-gated list endpoints."""
    TOKEN = "tok-123"

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.endswith("/auth-with-password") and body == {"identity": "ro@x", "password": "pw"}:
            return self._send(200, {"token": self.TOKEN})
        self._send(400, {"message": "Failed to authenticate."})

    def do_GET(self):
        if self.headers.get("Authorization") != self.TOKEN:
            return self._send(200, {"items": []})        # PocketBase list rules hide records rather than 401
        now = datetime.now(timezone.utc)
        pb = lambda t: t.strftime("%Y-%m-%d %H:%M:%S.000Z")  # noqa: E731
        if self.path.startswith("/api/collections/systems/records"):
            return self._send(200, {"items": [
                {"id": "s1", "name": "web", "status": "up", "updated": pb(now), "info": {"cpu": 91, "mp": 40, "dp": 50, "dt": 60}},
                {"id": "s2", "name": "db", "status": "up", "updated": pb(now - timedelta(minutes=30)), "info": {"cpu": 2}},
                {"id": "s3", "name": "nas", "status": "up", "updated": pb(now), "info": {"cpu": 5, "dp": 100}}]})
        if self.path.startswith("/api/collections/alerts/records"):
            assert "filter=triggered%3Dtrue" in self.path
            return self._send(200, {"items": [{"system": "s1", "name": "CPU", "triggered": True},
                                              {"system": "s3", "name": "Disk", "triggered": True}]})
        self._send(404, {})


@pytest.fixture()
def hub():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeBeszel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_api_source(load, hub):
    hh, _ = load(f"beszel: {{enabled: true, url: '{hub}', user: 'ro@x', ignore_alerts: {{nas: [Disk]}}}}\n",
                 env={"WARDEN_SECRET_BESZEL_PASSWORD": "pw", "BESZEL_PASSWORD": "pw"})
    r = hh.fetch()
    assert r.get("error") is None, r
    assert [(h["name"], h["state"]) for h in r["hosts"]] == [("db", "stale"), ("web", "hot"), ("nas", "ok")]
    assert r["hosts"][1]["alerts"] == ["CPU"] and r["hosts"][1]["temp_c"] == 60 and r["link"] == hub


def test_api_bad_password_shows_error(load, hub):
    hh, _ = load(f"beszel: {{enabled: true, url: '{hub}', user: 'ro@x'}}\n",
                 env={"WARDEN_SECRET_BESZEL_PASSWORD": "wrong", "BESZEL_PASSWORD": "wrong"})
    r = hh.fetch()
    assert "HTTPError" in r["error"] and r["hosts"] == []


def test_auto_widget_once_then_removal_sticks(load, tmp_path):
    snapshot(tmp_path / "hosts.json")
    _, views = load(f"beszel: {{enabled: true, snapshot: {tmp_path / 'hosts.json'}}}\n")
    assert views.layout()["widgets"][0] == "hosthealth"                         # appears by itself on the default layout
    views.save_layout({"kpis": ["bans"], "widgets": ["kind"]})                   # owner removed it in Customise
    assert views.layout()["widgets"] == ["kind"]
    views.save_layout({"kpis": ["bans"], "widgets": ["hosthealth", "kind"]})     # and can pin it back
    assert views.layout()["widgets"] == ["hosthealth", "kind"]
    views.reset_layout()
    assert views.layout()["widgets"][0] == "hosthealth"


def test_widget_hidden_when_integration_turned_off(load, tmp_path):
    snapshot(tmp_path / "hosts.json")
    _, views = load(f"beszel: {{enabled: true, snapshot: {tmp_path / 'hosts.json'}}}\n")
    views.save_layout({"kpis": ["bans"], "widgets": ["hosthealth", "kind"]})
    _, views = load("beszel: {enabled: false}\n")
    assert views.layout()["widgets"] == ["kind"]
