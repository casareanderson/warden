"""MCP connector: lets an AI agent (Hermes, Claude, Cursor, …) ask warden questions.

Streamable HTTP, `POST /mcp`, answered with plain `application/json` (the spec allows
that instead of SSE; every tool answers in one shot). No SDK — this is JSON-RPC.

READ-ONLY, AND A TEST ENFORCES IT. No tool may ban, block, patch, approve or change
anything. A model that can reach your firewall through a chat window is a different
risk class; decisions stay with a person, in the dashboard or the chat channel.

Three protocol traps that make a client HANG, each pinned by a test:
  1. A notification (no `id`) is never answered → 202, empty body.
  2. A TOOL failure is a result with isError: true, not a JSON-RPC error — the model
     has to be able to read what went wrong.
  3. GET → 405. warden never starts a stream, and saying so beats a hang.
"""
import json

from . import views

PROTOCOL = "2025-06-18"
KNOWN = {"2025-06-18", "2025-03-26", "2024-11-05"}
SERVER = {"name": "warden", "version": "2.0.0"}


def _obj(props=None, required=None):
    return {"type": "object", "properties": props or {}, "required": required or [], "additionalProperties": False}


TOOLS = [
    {"name": "warden_summary",
     "description": "Security posture at a glance: detect-only or enforcing, headline counts (detections, edge blocks, "
                    "red-list traffic, open findings, known-exploited CVEs, IDS alerts), collector health, and how many "
                    "decisions are waiting for the owner. Start here.",
     "inputSchema": _obj(), "fn": lambda a: views.summary()},
    {"name": "warden_detections",
     "description": "Recent scored log detections (probes, auth failures, scanners) with source, IP, country, kind and score.",
     "inputSchema": _obj({"hours": {"type": "integer", "minimum": 1, "maximum": 2160, "default": 24},
                          "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                          "min_score": {"type": "integer", "minimum": 0, "default": 0},
                          "ip": {"type": "string", "description": "only this address"}}),
     "fn": lambda a: views.detections(a.get("hours", 24), a.get("limit", 100), a.get("min_score", 0), a.get("ip", ""))},
    {"name": "warden_top_ips",
     "description": "The highest-scoring source addresses over a window, with behaviour kinds and last-seen time.",
     "inputSchema": _obj({"days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30},
                          "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}}),
     "fn": lambda a: views.top_ips(a.get("days", 30), a.get("limit", 25))},
    {"name": "warden_lookup_ip",
     "description": "Everything warden knows about one IP: country, red-list, whether it is our own, 30-day score, "
                    "its log events, edge events, ban history and LAN identity.",
     "inputSchema": _obj({"ip": {"type": "string"}}, ["ip"]), "fn": lambda a: views.lookup_ip(a["ip"])},
    {"name": "warden_search",
     "description": "Search across log events, edge events, LAN hosts, LAN alerts, CVEs, IDS and threat-intel hits. "
                    "Free text, or field:value with ip: cc: kind: src: host: type: (type is log|edge|host|net-alert|"
                    "vuln|ids|intel). Returns the newest 500.",
     "inputSchema": _obj({"q": {"type": "string"}}, ["q"]), "fn": lambda a: views.search(a["q"][:200])},
    {"name": "warden_bans",
     "description": "Ban proposals/active bans and the edge blocklist with status (pending/active/rejected/lapsed). "
                    "Read-only: approving happens in the dashboard or chat, never here.",
     "inputSchema": _obj(), "fn": lambda a: views.bans()},
    {"name": "warden_vulnerabilities",
     "description": "Vulnerability inventory. Without `target`: totals, per-box counts, top fixable/known-exploited "
                    "CVEs, Docker image advice and patch-job history. With `target` (e.g. ct:100, node:10.0.0.2, "
                    "img:nas): every finding on that box.",
     "inputSchema": _obj({"target": {"type": "string"}}),
     "fn": lambda a: views.vulns(a.get("target", ""))},
    {"name": "warden_attack_surface",
     "description": "Internet-facing surface: open findings, public names as the internet resolves them, WAF rules, "
                    "zone settings, and LAN listening services.",
     "inputSchema": _obj(), "fn": lambda a: views.attack_surface()},
    {"name": "warden_network",
     "description": "LAN inventory: known hosts (MAC, IP, vendor, first/last seen, approved) and LAN alerts.",
     "inputSchema": _obj(), "fn": lambda a: views.network()},
    {"name": "warden_ids",
     "description": "Network IDS (Suricata) alerts and threat-intel hits by device.",
     "inputSchema": _obj(), "fn": lambda a: views.ids()},
    {"name": "warden_integrity",
     "description": "File-integrity baselines and open changes per box, plus hardening (Lynis) scores.",
     "inputSchema": _obj(), "fn": lambda a: views.integrity()},
    {"name": "warden_health",
     "description": "Is warden itself working: last run of each collector in 24 h, lines read/scored, and "
                    "alerts that were suppressed and why.",
     "inputSchema": _obj(), "fn": lambda a: views.health()},
]
BY_NAME = {t["name"]: t for t in TOOLS}


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, msg):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


def _validate(schema, args):
    if not isinstance(args, dict):
        return "arguments must be an object"
    props = schema.get("properties", {})
    for r in schema.get("required", []):
        if r not in args:
            return f"missing required argument: {r}"
    for k, v in args.items():
        if k not in props:
            return f"unknown argument: {k}"
        t = props[k].get("type")
        if t == "integer" and not (isinstance(v, int) and not isinstance(v, bool)):
            return f"{k} must be an integer"
        if t == "string" and not isinstance(v, str):
            return f"{k} must be a string"
    return None


def handle_one(msg, caller="?"):
    """One JSON-RPC message → response dict, or None for a notification."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:                       # trap 1: notifications get no reply
        return None
    if method == "initialize":
        want = params.get("protocolVersion")
        return _ok(mid, {"protocolVersion": want if want in KNOWN else PROTOCOL,
                         "capabilities": {"tools": {"listChanged": False}},
                         "serverInfo": SERVER,
                         "instructions": "warden is a read-only home/homelab security monitor. Call warden_summary "
                                         "first. Nothing here can ban, block or patch; suggest actions to the user."})
    if method == "ping":
        return _ok(mid, {})
    if method == "tools/list":
        return _ok(mid, {"tools": [{k: t[k] for k in ("name", "description", "inputSchema")} for t in TOOLS]})
    if method == "tools/call":
        t = BY_NAME.get(params.get("name"))
        if not t:
            return _err(mid, -32602, f"unknown tool: {params.get('name')}")
        args = params.get("arguments") or {}
        bad = _validate(t["inputSchema"], args)
        if bad:                                # trap 2: tool problems are results the model can read
            return _ok(mid, {"content": [{"type": "text", "text": bad}], "isError": True})
        try:
            data = t["fn"](args)
        except Exception as e:  # noqa: BLE001
            return _ok(mid, {"content": [{"type": "text", "text": f"{t['name']} failed: {type(e).__name__}: {e}"[:500]}],
                             "isError": True})
        text = json.dumps(data, default=str)
        if len(text) > 200_000:
            text = text[:200_000] + '… [truncated — narrow the query]'
        return _ok(mid, {"content": [{"type": "text", "text": text}], "isError": False})
    return _err(mid, -32601, f"method not found: {method}")


def handle(body, caller="?"):
    """Raw POST body → (status, response bytes or b'')."""
    try:
        msg = json.loads(body or b"null")
    except ValueError:
        return 400, json.dumps(_err(None, -32700, "parse error")).encode()
    if isinstance(msg, list):                 # batch (2025-03-26 clients)
        out = [r for r in (handle_one(m, caller) for m in msg) if r is not None]
        return (200, json.dumps(out, default=str).encode()) if out else (202, b"")
    r = handle_one(msg, caller)
    return (202, b"") if r is None else (200, json.dumps(r, default=str).encode())
