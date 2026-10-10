"""Console sign-in: local users, sessions, roles, optional 2FA.

THREE MODES (warden.yml `ui.auth`)
  local   warden's own login page. Users live in warden.db; there is no web sign-up — the first admin is
          made on the command line (`warden-setup user add NAME --role admin`), so a fresh install has no
          window where a stranger can claim it. The default.
  proxy   your reverse proxy already signed the person in (Authelia, Authentik, oauth2-proxy…) and passes
          their name in `ui.trust_proxy_user_header` (default Remote-User). warden binds to localhost, so
          only the proxy can set that header. Everyone the proxy lets in is an admin.
  basic   the old single shared password (`ui.basic_user` + the WARDEN_UI_PASSWORD secret). Kept for
          existing installs; one account, no 2FA, no roles.
  An install that set `ui.basic_user` and nothing else stays on basic.

ROLES  viewer (look) < approver (+ approve/reject, request patches, accept exposures) < admin (+ settings,
       secrets, API tokens, the country-block switch, the home-page layout, users).

AT REST  passwords: scrypt (n=2^14, r=8, p=1, 16-byte salt). Sessions and 2FA secrets: the session cookie
         is random and only its SHA-256 is stored, so a copy of warden.db is not a way in. The 2FA secret
         has to be stored as-is (the server needs it to check codes) — it is useless without the password.
"""
import base64
import hashlib
import hmac
import secrets as _rand
import sqlite3
import struct
import threading
import time

from . import config

ROLES = ("viewer", "approver", "admin")
COOKIE = "warden_session"
MIN_PASSWORD = 12
LOCK_AFTER = 5                 # failed passwords in a row → account locked …
LOCK_MINUTES = 15              # … for this long
IP_WINDOW, IP_MAX = 900, 20    # and any one address gets 20 failed attempts per 15 minutes, across all names
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}


def mode():
    m = (config.get("ui.auth") or "").strip().lower()
    if m in ("local", "proxy", "basic"):
        return m
    return "basic" if config.get("ui.basic_user") else "local"


def at_least(role, need):
    return role in ROLES and ROLES.index(role) >= ROLES.index(need)


# ── storage ──────────────────────────────────────────────────────────────────
def _db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript("""
      create table if not exists users(id integer primary key, username text unique collate nocase,
        pw text, role text, totp text, totp_pending text, must_change integer default 0, disabled integer default 0,
        failed integer default 0, locked_until real default 0, created text, last_login text);
      create table if not exists sessions(id integer primary key, hash text unique, user_id integer,
        created real, last_seen real, expires real, ip text, ua text);
      create table if not exists auth_log(id integer primary key, ts text, username text, ip text, ok integer,
        why text);""")
    return con


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def _log(con, username, ip, ok, why):
    con.execute("insert into auth_log(ts, username, ip, ok, why) values(?,?,?,?,?)",
                (_now(), (username or "")[:64], (ip or "")[:64], 1 if ok else 0, why[:80]))


# ── passwords ────────────────────────────────────────────────────────────────
def hash_password(pw):
    salt = _rand.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, **_SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
                                       base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def _verify_password(pw, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=_SCRYPT["maxmem"], dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


_DUMMY = None


def _dummy():
    """A real hash to verify against when the user doesn't exist, so a wrong name costs the same time."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(_rand.token_urlsafe(16))
    return _DUMMY


def check_password_policy(pw, username=""):
    if len(pw) < MIN_PASSWORD:
        return f"at least {MIN_PASSWORD} characters"
    if len(pw) > 256:
        return "at most 256 characters"
    if len(username) >= 4 and username.lower() in pw.lower():      # "vi" is inside half the dictionary
        return "must not contain the username"
    if len(set(pw)) < 5:
        return "too repetitive"
    return None


def generate_password():
    return _rand.token_urlsafe(15)          # 20 characters, ~120 bits


# ── 2FA (RFC 6238 TOTP, 30 s, 6 digits, SHA-1 — what every authenticator app speaks) ──────────────────
def _totp_at(secret_b32, counter):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def totp_ok(secret_b32, code, now=None, window=1):
    code = (code or "").strip().replace(" ", "")
    if not (secret_b32 and code.isdigit() and len(code) == 6):
        return False
    t = int((now or time.time()) // 30)
    return any(hmac.compare_digest(_totp_at(secret_b32, t + d), code) for d in range(-window, window + 1))


def new_totp_secret():
    return base64.b32encode(_rand.token_bytes(20)).decode().rstrip("=")


# ── users ────────────────────────────────────────────────────────────────────
def _valid_name(name):
    return 1 <= len(name) <= 64 and all(c.isalnum() or c in "._-@" for c in name)


def users():
    with _db() as con:
        return [dict(r) for r in con.execute(
            "select id, username, role, disabled, must_change, (totp is not null) totp, failed, locked_until, "
            "created, last_login from users order by username")]


def count_admins(con=None):
    con = con or _db()
    return con.execute("select count(*) from users where role='admin' and disabled=0").fetchone()[0]


def add_user(username, role="viewer", password=None, must_change=True):
    """Returns the password (generated if not given). Raises ValueError with a readable reason."""
    username = (username or "").strip()
    if not _valid_name(username):
        raise ValueError("username: 1–64 letters, digits or . _ - @")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    pw = password or generate_password()
    why = check_password_policy(pw, username)
    if why:
        raise ValueError("password " + why)
    with _db() as con:
        try:
            con.execute("insert into users(username, pw, role, must_change, created) values(?,?,?,?,?)",
                        (username, hash_password(pw), role, 1 if must_change else 0, _now()))
        except sqlite3.IntegrityError:
            raise ValueError("that username exists") from None
    return pw


def _get(con, username):
    return con.execute("select * from users where username=?", ((username or "").strip(),)).fetchone()


def update_user(username, *, role=None, disabled=None, reset_password=False, reset_totp=False, unlock=False):
    """Admin changes. Refuses anything that would leave no enabled admin. Returns a new password if reset."""
    with _db() as con:
        u = _get(con, username)
        if not u:
            raise ValueError("no such user")
        if role is not None and role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        losing_admin = u["role"] == "admin" and not u["disabled"] and (
            (role is not None and role != "admin") or disabled)
        if losing_admin and count_admins(con) <= 1:
            raise ValueError("that is the last admin — make someone else admin first")
        new_pw = None
        if role is not None:
            con.execute("update users set role=? where id=?", (role, u["id"]))
        if disabled is not None:
            con.execute("update users set disabled=? where id=?", (1 if disabled else 0, u["id"]))
        if reset_password:
            new_pw = generate_password()
            con.execute("update users set pw=?, must_change=1, failed=0, locked_until=0 where id=?",
                        (hash_password(new_pw), u["id"]))
        if reset_totp:
            con.execute("update users set totp=null, totp_pending=null where id=?", (u["id"],))
        if unlock:
            con.execute("update users set failed=0, locked_until=0 where id=?", (u["id"],))
        if disabled or reset_password or (role is not None and role != u["role"]):
            con.execute("delete from sessions where user_id=?", (u["id"],))     # takes effect now, not at expiry
        return new_pw


def delete_user(username):
    with _db() as con:
        u = _get(con, username)
        if not u:
            raise ValueError("no such user")
        if u["role"] == "admin" and not u["disabled"] and count_admins(con) <= 1:
            raise ValueError("that is the last admin")
        con.execute("delete from sessions where user_id=?", (u["id"],))
        con.execute("delete from users where id=?", (u["id"],))


def change_password(user_id, current, new):
    with _db() as con:
        u = con.execute("select * from users where id=?", (user_id,)).fetchone()
        if not u or not _verify_password(current or "", u["pw"]):
            raise ValueError("current password is wrong")
        why = check_password_policy(new or "", u["username"])
        if why:
            raise ValueError("new password " + why)
        if _verify_password(new, u["pw"]):
            raise ValueError("pick a password you haven't just used")
        con.execute("update users set pw=?, must_change=0 where id=?", (hash_password(new), user_id))
        con.execute("delete from sessions where user_id=?", (user_id,))         # sign out everywhere else


def totp_begin(user_id):
    s = new_totp_secret()
    with _db() as con:
        u = con.execute("select username from users where id=?", (user_id,)).fetchone()
        con.execute("update users set totp_pending=? where id=?", (s, user_id))
    label = f"warden ({config.get('estate.name') or 'warden'}):{u['username']}"
    from urllib.parse import quote  # noqa: PLC0415
    return {"secret": s, "uri": f"otpauth://totp/{quote(label)}?secret={s}&issuer=warden&digits=6&period=30"}


def totp_confirm(user_id, code):
    with _db() as con:
        u = con.execute("select totp_pending from users where id=?", (user_id,)).fetchone()
        if not u or not u["totp_pending"] or not totp_ok(u["totp_pending"], code):
            raise ValueError("that code didn't match — check the time on your phone and try the next one")
        con.execute("update users set totp=totp_pending, totp_pending=null where id=?", (user_id,))


def totp_disable(user_id, password):
    with _db() as con:
        u = con.execute("select pw from users where id=?", (user_id,)).fetchone()
        if not u or not _verify_password(password or "", u["pw"]):
            raise ValueError("password is wrong")
        con.execute("update users set totp=null, totp_pending=null where id=?", (user_id,))


# ── sign in / sessions ───────────────────────────────────────────────────────
_ip_fail = {}
_ip_lock = threading.Lock()


def _ip_blocked(ip):
    with _ip_lock:
        now = time.time()
        hits = [t for t in _ip_fail.get(ip, []) if now - t < IP_WINDOW]
        _ip_fail[ip] = hits
        return len(hits) >= IP_MAX


def _ip_failed(ip):
    with _ip_lock:
        _ip_fail.setdefault(ip, []).append(time.time())


def login(username, password, code="", ip="", ua=""):
    """→ (session_token, user dict) or raises ValueError(reason shown to the person).
    Every failure says the same thing for a wrong name or a wrong password."""
    bad = f"wrong username or password (after {LOCK_AFTER} misses an account rests for {LOCK_MINUTES} minutes)"
    if _ip_blocked(ip):
        raise ValueError("too many failed attempts from your address — wait 15 minutes")
    with _db() as con:
        u = _get(con, username)
        if not u:
            _verify_password(password or "", _dummy())
            _ip_failed(ip); _log(con, username, ip, False, "no such user")
            con.commit()                 # ⚠️ a raise inside `with con` ROLLS BACK: counters + log would vanish
            raise ValueError(bad)
        if u["locked_until"] and u["locked_until"] > time.time():
            _verify_password(password or "", _dummy())              # same cost and same answer as a wrong password:
            _ip_failed(ip); _log(con, username, ip, False, "locked")   # a distinct message would confirm the name exists
            con.commit()                 # ⚠️ a raise inside `with con` ROLLS BACK: counters + log would vanish
            raise ValueError(bad)
        if not _verify_password(password or "", u["pw"]):
            failed = u["failed"] + 1
            lock = time.time() + LOCK_MINUTES * 60 if failed >= LOCK_AFTER else 0
            con.execute("update users set failed=?, locked_until=? where id=?",
                        (0 if lock else failed, lock, u["id"]))
            _ip_failed(ip); _log(con, username, ip, False, "password" + (" → locked" if lock else ""))
            con.commit()                 # ⚠️ a raise inside `with con` ROLLS BACK: counters + log would vanish
            raise ValueError(bad)
        if u["disabled"]:
            _log(con, username, ip, False, "disabled")
            con.commit()
            raise ValueError("this account is disabled")
        if u["totp"]:
            if not code:
                raise ValueError("2fa")                       # the page then asks for the code
            if not totp_ok(u["totp"], code):
                _ip_failed(ip); _log(con, username, ip, False, "2fa code")
                con.commit()
                raise ValueError("that 2FA code didn't match")
        tok = _rand.token_urlsafe(32)
        hours = float(config.get("ui.session_hours") or 12)
        now = time.time()
        con.execute("insert into sessions(hash, user_id, created, last_seen, expires, ip, ua) values(?,?,?,?,?,?,?)",
                    (_h(tok), u["id"], now, now, now + hours * 3600, ip[:64], (ua or "")[:200]))
        con.execute("update users set failed=0, locked_until=0, last_login=? where id=?", (_now(), u["id"]))
        con.execute("delete from sessions where expires < ?", (now,))
        _log(con, u["username"], ip, True, "signed in")
        return tok, {"id": u["id"], "username": u["username"], "role": u["role"], "must_change": u["must_change"]}


def _h(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def session(tok):
    """The signed-in user for a cookie value, or None. Idle sessions end after `ui.idle_minutes` (default 120)."""
    if not tok or len(tok) > 100:
        return None
    idle = float(config.get("ui.idle_minutes") or 120) * 60
    now = time.time()
    with _db() as con:
        r = con.execute("select s.id sid, s.last_seen, s.expires, u.id, u.username, u.role, u.must_change, "
                        "u.disabled, (u.totp is not null) totp from sessions s join users u on u.id = s.user_id "
                        "where s.hash=?", (_h(tok),)).fetchone()
        if not r:
            return None
        if r["disabled"] or r["expires"] < now or now - r["last_seen"] > idle:
            con.execute("delete from sessions where id=?", (r["sid"],))
            return None
        if now - r["last_seen"] > 60:                                   # don't write on every request
            con.execute("update sessions set last_seen=? where id=?", (now, r["sid"]))
        return {"id": r["id"], "username": r["username"], "role": r["role"], "must_change": r["must_change"],
                "totp": bool(r["totp"])}


def logout(tok):
    if tok:
        with _db() as con:
            con.execute("delete from sessions where hash=?", (_h(tok),))


def recent_log(limit=50):
    with _db() as con:
        return [dict(r) for r in con.execute("select ts, username, ip, ok, why from auth_log order by id desc "
                                             "limit ?", (limit,))]


def has_users():
    with _db() as con:
        return con.execute("select count(*) from users where disabled=0").fetchone()[0] > 0
