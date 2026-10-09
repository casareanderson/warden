#!/usr/bin/env python3
"""warden console + REST API + MCP connector (v2).

THREE AUDIENCES, THREE AUTH RULES
  Browser   GET /  /api  /api/search  /api/vuln  /api/settings
            behind your reverse proxy's auth, or `ui.basic_user` + WARDEN_UI_PASSWORD.
  Agents    GET /api/v1/<view>   POST /mcp      — always a bearer token (`wdn_…`), never proxy auth:
            an MCP client has no browser and cannot follow a login redirect, so your proxy must
            let /api/v1 and /mcp through to here and this server checks the token.
  Nobody    there is no endpoint that bans, blocks or unblocks. Edge changes stay in cfsec.py /
            edgeban.py with a dry run and an owner's approval.

THE FEW WRITES (browser only, same-origin + an X-Warden header, so a cross-site form can't fire them)
  POST /api/patch       queue a patch REQUEST — patcher.py turns it into a plan the owner must approve
  POST /api/layout      save / reset the Overview layout
  POST /api/tokens      mint (shown once) / revoke an API token
  POST /api/approvals   approve / reject something warden proposed (same as reacting in chat)
  POST /api/geo         the country-block switch + which red-list countries it blocks (applied by
                        warden-geo-apply within a minute, read back from Cloudflare)
  POST /api/config      change one of config.EDITABLE (→ data/overrides.yml; warden.yml is never written)
  POST /api/secret      set a secret (→ data/secrets.env, 0600). Write-only: no route ever returns one

  GET /api/v1/          index of views          GET /api/v1/openapi.json
  /api/v1/summary  detections?hours=&limit=&min_score=&ip=  top-ips?days=&limit=  ip/<addr>  search?q=
  /api/v1/bans  vulns?target=  attack-surface  network  ids  integrity  health  setup
"""
import base64
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wlib import config, mcp, notify, secrets, setup, tokens, views  # noqa: E402

PAGE = Path(__file__).with_name("warden-ui.html")
QUEUE = config.DATA / "patch-queue"


def _a(qs, k, d=""):
    return (qs.get(k) or [d])[0]


V1 = {
    "summary":        lambda qs, rest: views.summary(),
    "detections":     lambda qs, rest: views.detections(_a(qs, "hours", 24), _a(qs, "limit", 100),
                                                        _a(qs, "min_score", 0), _a(qs, "ip")[:64]),
    "top-ips":        lambda qs, rest: views.top_ips(_a(qs, "days", 30), _a(qs, "limit", 25)),
    "ip":             lambda qs, rest: views.lookup_ip(rest),
    "search":         lambda qs, rest: views.search(_a(qs, "q")[:200]),
    "bans":           lambda qs, rest: views.bans(),
    "vulns":          lambda qs, rest: views.vulns(_a(qs, "target")[:64]),
    "cve":            lambda qs, rest: views.cve(rest or _a(qs, "id")),
    "attack-surface": lambda qs, rest: views.attack_surface(),
    "network":        lambda qs, rest: views.network(),
    "ids":            lambda qs, rest: views.ids(),
    "integrity":      lambda qs, rest: views.integrity(),
    "health":         lambda qs, rest: views.health(),
    "setup":          lambda qs, rest: {"checks": setup.checks(), "score": setup.score(setup.checks())},
    "approvals":      lambda qs, rest: {"pending": notify.pending()},
}


def openapi():
    paths = {f"/api/v1/{k}" + {"ip": "/{ip}", "cve": "/{id}"}.get(k, ""): {"get": {
        "summary": k, "security": [{"bearer": []}], "responses": {"200": {"description": "JSON"}}}} for k in V1}
    return {"openapi": "3.1.0", "info": {"title": "warden", "version": mcp.SERVER["version"],
                                         "description": "Read-only security views. Bearer token: wdn_…"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}, "paths": paths}


def settings_payload():
    rows = setup.checks()
    base = (config.get("api.public_url") or "").rstrip("/")
    return {"checks": rows, "score": setup.score(rows), "tokens": tokens.listing(),
            "approvals": notify.pending(), "notify": config.get("notify.backend"),
            "mcp_url": (base + "/mcp") if base else "", "api_url": (base + "/api/v1") if base else "",
            "layout": views.layout(), "widgets": views.WIDGETS, "kpis": views.KPIS,
            "editable": [{"key": k, "type": t, "value": config.get(k)} for k, t in config.EDITABLE.items()],
            "overrides": config.OVERRIDES.exists()}


class H(BaseHTTPRequestHandler):
    server_version = "warden"
    sys_version = ""

    # ── plumbing ────────────────────────────────────────────────────────────
    def log_message(self, *a):
        pass

    def send(self, body, ctype="application/json", status=200, extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body(self, cap=8192):
        n = int(self.headers.get("Content-Length") or 0)
        if n > cap:
            raise ValueError("body too large")
        return self.rfile.read(n) if n else b""

    def bearer(self):
        h = self.headers.get("Authorization", "")
        return tokens.check(h[7:].strip()) if h.lower().startswith("bearer ") else None

    def browser_ok(self):
        """Proxy auth is trusted (we bind to localhost). Optional basic auth for proxy-less installs."""
        user = config.get("ui.basic_user")
        if not user:
            return True
        pw = secrets.get(config.get("ui.password_secret") or "WARDEN_UI_PASSWORD") or ""
        h = self.headers.get("Authorization", "")
        if h.lower().startswith("basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
            except ValueError:
                return False
            return bool(pw) and hmac.compare_digest(u, user) and hmac.compare_digest(p, pw)
        return False

    def deny_browser(self):
        self.send({"error": "authentication required"}, status=401,
                  extra={"WWW-Authenticate": 'Basic realm="warden"'})

    def same_origin(self, header):
        host, origin = self.headers.get("Host", ""), self.headers.get("Origin", "")
        return (self.headers.get("Sec-Fetch-Site") in (None, "same-origin")
                and (not origin or urlparse(origin).netloc == host)
                and self.headers.get("X-Warden") == header)

    def who(self):
        return self.headers.get(config.get("ui.trust_proxy_user_header") or "Remote-User") or config.get("ui.basic_user") \
            or "dashboard"

    # ── GET ─────────────────────────────────────────────────────────────────
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/mcp":
            self.send({"error": "this server does not open streams; POST JSON-RPC"}, status=405,
                      extra={"Allow": "POST"})
            return
        if u.path.startswith("/api/v1"):
            return self.v1(u, qs)
        if not self.browser_ok():
            return self.deny_browser()
        if u.path in ("/", "/index.html"):
            self.send(PAGE.read_bytes(), "text/html; charset=utf-8")
        elif u.path == "/api":
            p = views.payload()
            p["layout"], p["widgets"], p["approvals"] = views.layout(), views.WIDGETS, notify.pending()
            self.send(p)
        elif u.path == "/api/vuln":
            self.send(views.vulns(_a(qs, "target")[:64]))
        elif u.path == "/api/cve":
            self.send(views.cve(_a(qs, "id")))
        elif u.path == "/api/search":
            self.send(views.search(_a(qs, "q")[:200]))
        elif u.path == "/api/settings":
            self.send(settings_payload())
        else:
            self.send({"error": "not found"}, status=404)

    def v1(self, u, qs):
        if not config.get("api.enabled", True):
            return self.send({"error": "API disabled (api.enabled: false)"}, status=404)
        if not self.bearer():
            return self.send({"error": "bearer token required (Authorization: Bearer wdn_…)"}, status=401,
                             extra={"WWW-Authenticate": 'Bearer realm="warden"'})
        parts = u.path[len("/api/v1"):].strip("/").split("/", 1)
        name, rest = parts[0], unquote(parts[1]) if len(parts) > 1 else ""
        if name == "":
            return self.send({"views": sorted(V1), "openapi": "/api/v1/openapi.json", "mcp": "/mcp"})
        if name == "openapi.json":
            return self.send(openapi())
        fn = V1.get(name)
        if not fn:
            return self.send({"error": f"unknown view {name}", "views": sorted(V1)}, status=404)
        try:
            self.send(fn(qs, rest[:64]))
        except Exception as e:  # noqa: BLE001
            self.send({"error": f"{type(e).__name__}: {e}"[:300]}, status=500)

    # ── POST ────────────────────────────────────────────────────────────────
    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/mcp":
            who = self.bearer()
            if not who:
                return self.send({"error": "bearer token required"}, status=401,
                                 extra={"WWW-Authenticate": 'Bearer realm="warden"'})
            try:
                status, out = mcp.handle(self.body(cap=1_000_000), caller=who)
            except ValueError:
                return self.send({"error": "body too large"}, status=413)
            if status == 202:
                self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
                return
            return self.send(out, status=status)
        if not self.browser_ok():
            return self.deny_browser()
        routes = {"/api/patch": ("patch", self.post_patch), "/api/layout": ("layout", self.post_layout),
                  "/api/tokens": ("tokens", self.post_tokens), "/api/approvals": ("approvals", self.post_approval),
                  "/api/geo": ("geo", self.post_geo), "/api/config": ("config", self.post_config),
                  "/api/secret": ("secret", self.post_secret)}
        if u.path not in routes:
            return self.send({"error": "not found"}, status=404)
        header, fn = routes[u.path]
        if not self.same_origin(header):
            return self.send({"error": "forbidden"}, status=403)
        try:
            data = json.loads(self.body() or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self.send({"error": "bad request"}, status=400)
        fn(data)

    def post_patch(self, body):
        """Queue a patch REQUEST. It runs nothing: patcher.py turns it into a plan the owner must approve."""
        target = str(body.get("target", ""))[:64]
        ok = views.q("select 1 from vuln_targets where target=? and patchable=1", (target,))
        if not ok and target.startswith("ctr:") and target.count(":") == 2 and views.has("img_advice"):
            _, host, cname = target.split(":", 2)
            ok = views.q("select 1 from img_advice where host=? and container=? and action in ('recreate','pull')",
                         ("img:" + host, cname))
        if not ok:
            return self.send({"ok": False, "error": "not a patchable target"})
        QUEUE.mkdir(parents=True, exist_ok=True)
        (QUEUE / f"{int(time.time() * 1000)}.json").write_text(json.dumps({"target": target, "by": self.who()}))
        where = {"discord": "in your alerts channel", "none": "under Settings → Waiting for you"}.get(
            config.get("notify.backend"), "in your alerts and under Settings → Waiting for you")
        self.send({"ok": True, "msg": f"Queued. A plan will appear {where} within ~2 min — nothing changes "
                                      "until you approve it."})

    def post_layout(self, body):
        if body.get("reset"):
            views.reset_layout()
            return self.send({"ok": True, "layout": views.layout()})
        self.send({"ok": True, "layout": dict(views.save_layout(body), custom=True)})

    def post_tokens(self, body):
        if body.get("revoke") is not None:
            try:
                return self.send({"ok": tokens.revoke(int(body["revoke"]))})
            except (TypeError, ValueError):
                return self.send({"error": "bad id"}, status=400)
        name = str(body.get("name") or "agent")[:60]
        self.send({"ok": True, "token": tokens.mint(name),
                   "note": "Shown once. Store it in your agent's secret store; warden keeps only a hash."})

    def post_approval(self, body):
        mid, choice = str(body.get("id", ""))[:40], body.get("choice")
        if choice not in (notify.APPROVE, notify.REJECT, notify.NOW):
            return self.send({"error": "choice must be ✅, ❌ or ⚡"}, status=400)
        self.send({"ok": notify.decide(mid, choice, who=self.who())})


    def post_geo(self, body):
        if not config.get("cloudflare.zone_id"):
            return self.send({"ok": False, "error": "no Cloudflare zone configured (cloudflare.zone_id)"})
        ccs = body.get("block")
        if not isinstance(ccs, list) or not all(isinstance(c, str) and len(c) == 2 and c.isalpha() for c in ccs):
            return self.send({"error": "block must be a list of 2-letter country codes"}, status=400)
        state = {"enabled": bool(body.get("enabled")), "block": sorted({c.upper() for c in ccs})[:60],
                 "by": self.who(), "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}
        config.DATA.mkdir(parents=True, exist_ok=True)
        (config.DATA / "geo-block.json").write_text(json.dumps(state))
        self.send({"ok": True, "state": state,
                   "msg": "Saved. Cloudflare is updated within about a minute and read back — this card shows "
                          "the result."})

    def post_config(self, body):
        try:
            v = config.set_override(str(body.get("key", "")), body.get("value"))
        except KeyError:
            return self.send({"ok": False, "error": "that setting can only be changed in warden.yml"}, status=400)
        except (ValueError, TypeError) as e:
            return self.send({"ok": False, "error": str(e)[:200]}, status=400)
        self.send({"ok": True, "value": v})

    def post_secret(self, body):
        try:
            secrets.put(str(body.get("name", "")), str(body.get("value", "")))
        except ValueError as e:
            return self.send({"ok": False, "error": str(e)}, status=400)
        self.send({"ok": True, "msg": "Stored in data/secrets.env (0600). It is never shown again."})


def main():
    host, port = config.get("ui.host") or "127.0.0.1", int(config.get("ui.port") or 8792)
    import os  # noqa: PLC0415
    host = os.environ.get("WARDEN_UI_HOST", host)
    port = int(os.environ.get("WARDEN_UI_PORT", port))
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    main()
