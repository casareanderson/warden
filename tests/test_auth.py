"""Console sign-in (ui.auth: local): no sign-up hole, roles, lockout, 2FA, sessions."""
import importlib
import importlib.util
import json
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DATA", str(tmp_path))
    monkeypatch.setenv("WARDEN_CONF", str(tmp_path / "warden.yml"))
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\n")   # no ui.auth → local
    con = sqlite3.connect(tmp_path / "warden.db")
    con.executescript("""
      create table events(id integer primary key, ts text, source text, ip text, kind text, detail text, score int);
      create table runs(id integer primary key, ts text, source text, lines int, parsed int, note text);
      create table bans(id integer primary key, ts text, ip text, score int, reasons text, state text, note text);
      create table net_hosts(mac text, ip text, hostname text, vendor text, first_seen text, last_seen text, approved int);
      create table net_ports(mac text, port int, service text);
      create table net_alerts(id integer primary key, ts text, kind text, mac text, ip text, detail text);
      create table net_runs(id integer primary key, ts text, hosts int);
      create table surface_snap(id integer primary key, ts text, data text);""")
    con.commit(); con.close()
    import wlib.config as c
    importlib.reload(c)
    import wlib.auth, wlib.notify, wlib.tokens, wlib.views, wlib.mcp, wlib.setup  # noqa: E401
    for m in (wlib.auth, wlib.notify, wlib.tokens, wlib.views, wlib.mcp, wlib.setup):
        importlib.reload(m)
    spec = importlib.util.spec_from_file_location("warden_ui", ROOT / "warden-ui.py")
    ui = importlib.util.module_from_spec(spec); spec.loader.exec_module(ui)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ui.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{srv.server_port}", "auth": wlib.auth}
    srv.shutdown()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(url, data=None, cookie="", hdr=None, method=None):
    h = {"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {}), **(hdr or {})}
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=h,
                                 method=method)
    op = urllib.request.build_opener(NoRedirect)
    try:
        with op.open(req, timeout=10) as r:
            b = r.read()
            return r.status, (json.loads(b) if b and r.headers.get_content_type() == "application/json" else b), r.headers
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            b = json.loads(b)
        except ValueError:
            pass
        return e.code, b, e.headers


def login(env, user, pw, code=""):
    st, j, h = call(env["url"] + "/auth/login", {"username": user, "password": pw, "code": code},
                    hdr={"X-Warden": "login", "Sec-Fetch-Site": "same-origin"})
    ck = (h.get("Set-Cookie") or "").split(";")[0]
    return st, j, ck, h.get("Set-Cookie") or ""


def change(env, ck, cur, new):
    return call(env["url"] + "/api/password", {"current": cur, "new": new}, cookie=ck,
                hdr={"X-Warden": "password", "Sec-Fetch-Site": "same-origin"})


def test_fresh_install_is_closed(env):
    st, _, h = call(env["url"] + "/")
    assert st == 302 and h["Location"] == "login"                 # no session → sign-in page, never the console
    assert call(env["url"] + "/api")[0] == 401
    assert call(env["url"] + "/api/settings")[0] == 401
    st, j, _ = call(env["url"] + "/auth/status")
    assert j == {"mode": "local", "users": False}                  # the page shows "make an admin on the CLI"
    assert login(env, "admin", "anything-at-all-long")[0] == 401   # and there is nothing to sign in to
    st, body, h = call(env["url"] + "/login")
    assert st == 200 and b"warden-setup user add" in body and "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_first_sign_in_forces_a_new_password(env):
    pw = env["auth"].add_user("owner", "admin")
    st, j, ck, raw = login(env, "owner", pw)
    assert st == 200 and j["must_change"] is True
    assert "HttpOnly" in raw and "SameSite=Strict" in raw and "Secure" not in raw    # plain http on localhost
    assert call(env["url"] + "/api", cookie=ck)[0] == 403                           # console stays shut …
    assert call(env["url"] + "/api/me", cookie=ck)[1]["must_change"] == 1           # … except for this
    assert change(env, ck, pw, "short")[1]["ok"] is False
    assert change(env, ck, pw, "owner-owner-owner")[1]["error"].endswith("must not contain the username")
    st, j, h = change(env, ck, pw, "correct horse battery 9")
    assert j["ok"] is True
    new_ck = h["Set-Cookie"].split(";")[0]
    assert call(env["url"] + "/api", cookie=ck)[0] == 401                           # old session is gone
    assert call(env["url"] + "/api", cookie=new_ck)[0] == 200


def test_cookie_is_secure_behind_https_proxy(env):
    env["auth"].add_user("owner", "admin", password="a-long-password-1", must_change=False)
    st, j, h = call(env["url"] + "/auth/login", {"username": "owner", "password": "a-long-password-1"},
                    hdr={"X-Warden": "login", "Sec-Fetch-Site": "same-origin", "X-Forwarded-Proto": "https"})
    assert st == 200 and "Secure" in h["Set-Cookie"]


def test_login_needs_same_origin_header(env):
    env["auth"].add_user("owner", "admin", password="a-long-password-1", must_change=False)
    st, _, _ = call(env["url"] + "/auth/login", {"username": "owner", "password": "a-long-password-1"},
                    hdr={"Sec-Fetch-Site": "cross-site", "X-Warden": "login"})
    assert st == 403


def test_roles(env):
    a = env["auth"]
    for name, role in (("vi", "viewer"), ("ap", "approver"), ("ad", "admin")):
        a.add_user(name, role, password=f"{name}-long-password-1", must_change=False)
    ck = {n: login(env, n, f"{n}-long-password-1")[2] for n in ("vi", "ap", "ad")}
    w = lambda n, path, hdr, body: call(env["url"] + path, body, cookie=ck[n],
                                         hdr={"X-Warden": hdr, "Sec-Fetch-Site": "same-origin"})
    assert call(env["url"] + "/api", cookie=ck["vi"])[0] == 200                    # everyone can look
    assert w("vi", "/api/approvals", "approvals", {"id": "1", "choice": "✅"})[0] == 403
    assert w("ap", "/api/approvals", "approvals", {"id": "1", "choice": "✅"})[0] == 200
    assert w("ap", "/api/tokens", "tokens", {"name": "x"})[0] == 403
    assert w("ap", "/api/secret", "secret", {"name": "X", "value": "y"})[0] == 403
    assert w("ad", "/api/tokens", "tokens", {"name": "x"})[1]["ok"] is True
    assert call(env["url"] + "/api/users", cookie=ck["ap"])[0] == 403
    assert len(call(env["url"] + "/api/users", cookie=ck["ad"])[1]["users"]) == 3
    # the audit trail names the person, not "dashboard"
    assert call(env["url"] + "/api/me", cookie=ck["ap"])[1]["username"] == "ap"


def test_admin_cannot_remove_last_admin_or_self(env):
    a = env["auth"]
    a.add_user("ad", "admin", password="ad-long-password-1", must_change=False)
    with pytest.raises(ValueError, match="last admin"):
        a.update_user("ad", role="viewer")
    with pytest.raises(ValueError, match="last admin"):
        a.delete_user("ad")
    ck = login(env, "ad", "ad-long-password-1")[2]
    st, j, _ = call(env["url"] + "/api/users", {"action": "disable", "username": "ad"}, cookie=ck,
                    hdr={"X-Warden": "users", "Sec-Fetch-Site": "same-origin"})
    assert j["ok"] is False


def test_disable_ends_sessions_now(env):
    a = env["auth"]
    a.add_user("ad", "admin", password="ad-long-password-1", must_change=False)
    a.add_user("vi", "viewer", password="vi-long-password-1", must_change=False)
    ck = login(env, "vi", "vi-long-password-1")[2]
    assert call(env["url"] + "/api", cookie=ck)[0] == 200
    a.update_user("vi", disabled=True)
    assert call(env["url"] + "/api", cookie=ck)[0] == 401


def test_lockout_and_same_answer_for_unknown_names(env):
    a = env["auth"]
    a.add_user("vi", "viewer", password="vi-long-password-1", must_change=False)
    msgs = {login(env, "vi", "wrong-password-xx")[1]["error"] for _ in range(a.LOCK_AFTER)}
    msgs.add(login(env, "nobody", "wrong-password-xx")[1]["error"])
    st, j, _, _ = login(env, "vi", "vi-long-password-1")                      # right password, but locked
    msgs.add(j["error"])
    assert st == 401 and len(msgs) == 1                                         # one message for all three cases
    log = a.recent_log()                    # failures must survive: a raise inside `with con` used to roll them back
    assert sum(1 for r in log if not r["ok"]) == a.LOCK_AFTER + 2 and any(r["why"] == "locked" for r in log)
    a.update_user("vi", unlock=True)
    assert login(env, "vi", "vi-long-password-1")[0] == 200


def test_per_address_limit(env, monkeypatch):
    a = env["auth"]
    monkeypatch.setattr(a, "IP_MAX", 3)
    for i in range(3):
        login(env, f"nobody{i}", "wrong-password-xx")
    st, j, _, _ = login(env, "nobody9", "wrong-password-xx")
    assert st == 401 and "too many failed attempts" in j["error"]


def test_totp(env):
    a = env["auth"]
    # RFC 6238 appendix B vector (SHA-1, secret "12345678901234567890", T=59 → 94287082, last 6 digits)
    import base64
    s = base64.b32encode(b"12345678901234567890").decode()
    assert a._totp_at(s, 59 // 30) == "287082"
    assert a.totp_ok(s, "287082", now=59) and not a.totp_ok(s, "287083", now=59)
    a.add_user("vi", "viewer", password="vi-long-password-1", must_change=False)
    uid = a.users()[0]["id"]
    sec = a.totp_begin(uid)["secret"]
    with pytest.raises(ValueError):
        a.totp_confirm(uid, "000000")
    a.totp_confirm(uid, a._totp_at(sec, int(time.time() // 30)))
    st, j, ck, _ = login(env, "vi", "vi-long-password-1")
    assert j == {"ok": False, "need_code": True} and not ck                    # password alone isn't enough
    assert login(env, "vi", "vi-long-password-1", "123456")[0] == 401
    assert login(env, "vi", "vi-long-password-1", a._totp_at(sec, int(time.time() // 30)))[0] == 200


def test_secrets_at_rest(env, tmp_path):
    a = env["auth"]
    a.add_user("vi", "viewer", password="vi-long-password-1", must_change=False)
    ck = login(env, "vi", "vi-long-password-1")[2]
    raw = (tmp_path / "warden.db").read_bytes()
    assert b"vi-long-password-1" not in raw and ck.split("=", 1)[1].encode() not in raw


def test_logout(env):
    env["auth"].add_user("vi", "viewer", password="vi-long-password-1", must_change=False)
    ck = login(env, "vi", "vi-long-password-1")[2]
    st, _, h = call(env["url"] + "/auth/logout", {}, cookie=ck, hdr={"X-Warden": "logout", "Sec-Fetch-Site": "same-origin"})
    assert st == 200 and "Max-Age=0" in h["Set-Cookie"]
    assert call(env["url"] + "/api", cookie=ck)[0] == 401


def test_proxy_and_basic_modes_unchanged(env, tmp_path):
    import wlib.config as c
    (tmp_path / "warden.yml").write_text("estate: {name: test}\nnotify: {backend: none}\nui: {auth: proxy}\n")
    importlib.reload(c)
    assert call(env["url"] + "/api", hdr={"Remote-User": "chris"})[0] == 200
    assert call(env["url"] + "/api/me", hdr={"Remote-User": "chris"})[1]["username"] == "chris"
    st, _, h = call(env["url"] + "/login")
    assert st == 302                                                             # no login page in proxy mode
