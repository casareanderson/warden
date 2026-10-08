"""API tokens for the REST API and the MCP connector.

`wdn_` + 32 random url-safe bytes. Only the SHA-256 is stored, so a copy of the
database is not a copy of anyone's credential. A token is shown exactly once,
when it is minted; every use is counted; revoking is immediate.
"""
import hashlib
import secrets as _rand
import sqlite3
import time

from . import config

PREFIX = "wdn_"


def _db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.execute("""create table if not exists api_tokens(
        id integer primary key, name text, hint text, hash text unique, created text,
        last_used text, uses integer default 0, revoked text)""")
    return con


def _h(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def mint(name):
    tok = PREFIX + _rand.token_urlsafe(32)
    with _db() as con:
        con.execute("insert into api_tokens(name, hint, hash, created) values(?,?,?,?)",
                    ((name or "unnamed")[:60], tok[:8] + "…" + tok[-4:], _h(tok), _now()))
    return tok


def check(tok):
    """The token's name if valid, else None. Constant-time on the stored hash via the unique index."""
    if not tok or not tok.startswith(PREFIX) or len(tok) > 200:
        return None
    with _db() as con:
        r = con.execute("select id, name from api_tokens where hash=? and revoked is null", (_h(tok),)).fetchone()
        if not r:
            return None
        con.execute("update api_tokens set uses=uses+1, last_used=? where id=?", (_now(), r[0]))
    return r[1]


def listing():
    with _db() as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute(
            "select id, name, hint, created, last_used, uses, revoked from api_tokens order by id desc")]


def revoke(token_id):
    with _db() as con:
        return con.execute("update api_tokens set revoked=? where id=? and revoked is null",
                           (_now(), int(token_id))).rowcount == 1


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
