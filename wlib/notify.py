"""Alerts and owner approvals, behind one small interface.

    notify.send("text")                       fire-and-forget alert
    mid = notify.post("text", reply_to=None)  a message that can be approved
    notify.react(mid, notify.APPROVE)         offer a choice (Discord adds the reaction)
    notify.reactors(mid, notify.APPROVE)      who chose it: [owner()] / [] / None if the message is gone

warden.yml:
    notify:
      backend: discord | webhook | ntfy | none
      channel: "123…"              # discord: channel id
      owner_id: "456…"             # discord: the only user whose reactions count
      token_secret: DISCORD_BOT_TOKEN
      webhook_secret: ALERT_WEBHOOK   # webhook: a Discord/Slack-compatible webhook URL
      ntfy_url: https://ntfy.sh/your-topic

Every approval is ALSO recorded in the local `approvals` table, and the dashboard
can approve/reject it. That is the only approval path for backends that cannot
read reactions back (webhook, ntfy, none) — nothing waits on a channel that can't answer.
"""
import json
import sqlite3
import sys
import time
import urllib.parse

from . import config, secrets

APPROVE, REJECT, NOW = "✅", "❌", "⚡"
DISCORD_API = "https://discord.com/api/v10"


def _backend():
    return (config.get("notify.backend") or "none").lower()


def owner():
    return str(config.get("notify.owner_id") or "owner")


def channel():
    return str(config.get("notify.channel") or "")


# ── local approval ledger (always on) ───────────────────────────────────────
def _db():
    con = sqlite3.connect(config.DB, timeout=30)
    con.execute("""create table if not exists approvals(
        id text primary key, created text, text text, choices text,
        decision text, decided_by text, decided_at text)""")
    return con


def _record(mid, text, reply_to=None):
    with _db() as con:
        con.execute("insert or ignore into approvals(id, created, text, choices) values(?,?,?,?)",
                    (str(mid), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), text[:4000],
                     json.dumps([]) if not reply_to else json.dumps(["reply"])))


def _add_choice(mid, emoji):
    with _db() as con:
        r = con.execute("select choices from approvals where id=?", (str(mid),)).fetchone()
        if r:
            ch = [c for c in json.loads(r[0] or "[]") if c != "reply"]
            if emoji not in ch:
                ch.append(emoji)
            con.execute("update approvals set choices=? where id=?", (json.dumps(ch), str(mid)))


def decide(mid, emoji, who="dashboard"):
    """Record a decision made outside the chat channel (dashboard button, API)."""
    with _db() as con:
        n = con.execute("update approvals set decision=?, decided_by=?, decided_at=? "
                        "where id=? and decision is null",
                        (emoji, who, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), str(mid))).rowcount
    return n == 1


def pending():
    with _db() as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute(
            "select * from approvals where decision is null and choices != '[]' and choices != '[\"reply\"]' "
            "order by created desc limit 50")]


def _local_decision(mid):
    with _db() as con:
        r = con.execute("select decision from approvals where id=?", (str(mid),)).fetchone()
    return r[0] if r else None


# ── discord REST ────────────────────────────────────────────────────────────
def _discord(method, path, **kw):
    import requests  # noqa: PLC0415 - only needed for this backend
    tok = secrets.get(config.get("notify.token_secret") or "DISCORD_BOT_TOKEN")
    if not tok:
        raise RuntimeError("notify: discord backend but no bot token (set DISCORD_BOT_TOKEN)")
    hdr = {"Authorization": f"Bot {tok}", "Content-Type": "application/json"}
    last = None
    for attempt in range(5):
        try:
            r = requests.request(method, DISCORD_API + path, headers=hdr, timeout=15, **kw)
        except requests.RequestException as e:
            last = type(e).__name__
            time.sleep(2 + 3 * attempt)
            continue
        if r.status_code == 429:
            try:
                wait = float(r.json().get("retry_after", 2))
            except Exception:  # noqa: BLE001
                wait = 2
            time.sleep(min(wait, 30) + 0.5)
            continue
        if r.status_code >= 500:
            last = f"HTTP {r.status_code}"
            time.sleep(2 + 3 * attempt)
            continue
        return r
    raise RuntimeError(f"discord {method} failed: {last}")


def _webhook(text):
    import requests  # noqa: PLC0415
    url = secrets.get(config.get("notify.webhook_secret") or "ALERT_WEBHOOK")
    if not url:
        raise RuntimeError("notify: webhook backend but no ALERT_WEBHOOK secret")
    for chunk in [text[i:i + 1900] for i in range(0, len(text), 1900)] or [""]:
        requests.post(url, json={"content": chunk, "text": chunk}, timeout=15).raise_for_status()


def _ntfy(text):
    import requests  # noqa: PLC0415
    url = config.get("notify.ntfy_url")
    if not url:
        raise RuntimeError("notify: ntfy backend but no notify.ntfy_url")
    requests.post(url, data=text.encode()[:4000], headers={"Title": "warden"}, timeout=15).raise_for_status()


# ── public interface ────────────────────────────────────────────────────────
def send(text, channel_id=None):
    """Fire-and-forget. Returns True on success; never raises (an alert path must not crash a scan)."""
    b = _backend()
    try:
        if b == "discord":
            ch = channel_id or channel()
            for chunk in [text[i:i + 1900] for i in range(0, len(text), 1900)] or [""]:
                _discord("POST", f"/channels/{ch}/messages",
                         json={"content": chunk, "allowed_mentions": {"parse": []}}).raise_for_status()
        elif b == "webhook":
            _webhook(text)
        elif b == "ntfy":
            _ntfy(text)
        else:
            print(f"[notify] {text}", file=sys.stderr)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"notify: send failed: {e}", file=sys.stderr)
        return False


send_discord = send          # drop-in name for code written against the old helper


def post(text, channel=None, reply_to=None):
    """A message that may become an approval. Returns its id (Discord id, or local-<ms>)."""
    if _backend() == "discord":
        body = {"content": text[:1990], "allowed_mentions": {"parse": []}}
        if reply_to and not str(reply_to).startswith("local-"):
            body["message_reference"] = {"message_id": str(reply_to), "fail_if_not_exists": False}
        r = _discord("POST", f"/channels/{channel or globals()['channel']()}/messages", json=body)
        r.raise_for_status()
        mid = r.json()["id"]
    else:
        mid = f"local-{int(time.time() * 1000)}"
        send(text)
    _record(mid, text, reply_to)
    return mid


def react(mid, emoji, channel=None):
    _add_choice(mid, emoji)
    if _backend() == "discord" and not str(mid).startswith("local-"):
        e = urllib.parse.quote(emoji)
        _discord("PUT", f"/channels/{channel or globals()['channel']()}/messages/{mid}/reactions/{e}/@me").raise_for_status()


def reactors(mid, emoji, channel=None):
    """Who picked `emoji`. A dashboard decision counts as the owner's.
    Returns None only when the chat message is gone (callers treat that as cancelled)."""
    if _local_decision(mid) == emoji:
        return [owner()]
    if _backend() != "discord" or str(mid).startswith("local-"):
        return []
    e = urllib.parse.quote(emoji)
    users, after = [], None
    while True:
        q = "?limit=100" + (f"&after={after}" if after else "")
        r = _discord("GET", f"/channels/{channel or globals()['channel']()}/messages/{mid}/reactions/{e}{q}")
        if r.status_code == 404:
            code = (r.json() or {}).get("code") if r.headers.get("content-type", "").startswith("application/json") else None
            return None if code == 10008 else users
        r.raise_for_status()
        page = r.json()
        users += [u["id"] for u in page]
        if len(page) < 100:
            return users
        after = page[-1]["id"]
