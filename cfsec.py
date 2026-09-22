#!/usr/bin/env python3
"""cfsec — audit and configure the Cloudflare edge for example.com.

Two modes:
  --audit       read-only: DNS exposure, zone security settings, WAF rules,
                rate limits. Reports what the token cannot read rather than
                pretending that means "nothing configured".
  --apply-waf   create the proposed custom WAF rules. DRY-RUN BY DEFAULT;
                needs --commit to actually write.

⚠️ TOKEN SCOPES — the reason this script reports gaps instead of failing
The tokens that already exist in this estate are deliberately narrow:
  - the Caddy token (/etc/caddy/caddy.env)  = DNS:Edit only
  - the NetBird token (CT108)               = Tunnel:Edit + DNS:Edit
  - the CrowdSec token (CT106)              = Firewall Access Rules only
None can read zone settings or touch the WAF: those return 9109/10000. Audit
needs Zone:Read + Zone Settings:Read + Zone WAF:Read; applying rules needs
Zone WAF:Edit. Mint one at Cloudflare → My Profile → API Tokens → Custom, and
pass it as CF_API_TOKEN.

⚠️⚠️ WHY THE PROPOSED RULES ARE NARROW
On 2026-07-03 a host-wide rate-limit rule (20 req/10s) broke the NetBird
dashboard outright: a single-page app cold-loads far more than 20 JS chunks,
Cloudflare 429'd the overflow, a chunk came back as HTML, and the browser threw
ChunkLoadError. It looked like an origin outage and was not. The lesson is that
a rule matching whole hostnames will eventually block something you need. Every
rule below matches a specific hostile PATH or USER AGENT, never a whole host,
and nothing here touches /.well-known/ (ACME + OIDC discovery) or /api/ and
/_next/ (Immich, Authelia and NetBird all depend on them).
"""
import json
import os
import sys
import urllib.error
import urllib.request

ZONE = os.environ.get("CF_ZONE_ID", "")   # required: your Cloudflare zone id
API = "https://api.cloudflare.com/client/v4"
PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.2", "172.30.", "172.31.")


# No Cloudflare credential is stored in this file. Resolution order mirrors
# hermes_secrets: an explicit env override first (tests, one-offs), then
# Infisical, then the Caddy token as a last resort.
#
# ⚠️ NO SINGLE TOKEN COVERS EVERYTHING, and that is deliberate — see the
# docstring. The Infisical `WAF token` reads zone settings and the WAF but is
# 403 on DNS; the Caddy token is the reverse. So the audit uses BOTH and
# reports per-section, rather than picking one and calling the other half
# "not configured".
INFISICAL_PATH = "/Cloudflare"
INFISICAL_KEY = "WAF token"          # note the space — that is the real key name


def _infisical_token():
    try:
        sys.path.insert(0, "/opt/hermes-agent")
        import hermes_secrets
        return (hermes_secrets.get(INFISICAL_KEY, INFISICAL_PATH) or "").strip()
    except Exception:
        return ""


def _caddy_token():
    try:
        for line in open("/etc/caddy/caddy.env"):
            if line.startswith("CF_API_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"\'')
    except OSError:
        pass
    return ""


def token():
    return (os.environ.get("CF_API_TOKEN") or _infisical_token()
            or _caddy_token())


def call(path, method="GET", body=None, tok=None):
    """Return (ok, payload_or_error). Never raises: a 403 from a narrow token
    is an expected outcome here, not a crash."""
    req = urllib.request.Request(
        f"{API}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {tok}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
            return d.get("success", False), d
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)
            errs = d.get("errors") or [{"message": str(e)}]
            return False, errs[0].get("message", str(e))
        except Exception:
            return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)[:160]


# ------------------------------------------------------------------ audit --
def audit(tok, dns_tok=None):
    gaps = []
    dns_tok = dns_tok or tok
    print("=" * 72)
    print(f"Cloudflare edge audit — zone {ZONE}")
    print("=" * 72)

    # --- DNS exposure ---------------------------------------------------
    ok, d = call(f"/zones/{ZONE}/dns_records?per_page=200", tok=dns_tok)
    if not ok:
        print(f"\n[DNS]       UNREADABLE — {d}")
        gaps.append("DNS:Read")
    else:
        recs = d["result"]
        addr = [r for r in recs if r["type"] in ("A", "AAAA", "CNAME")]
        leaks = [r for r in addr if str(r["content"]).startswith(PRIVATE_PREFIXES)]
        unproxied = [r for r in addr
                     if not r["proxied"] and not str(r["content"]).startswith(PRIVATE_PREFIXES)]
        print(f"\n[DNS]       {len(recs)} records, {len(addr)} addressable")
        print(f"            {sum(1 for r in addr if r['proxied'])} proxied "
              f"(behind the edge), {len(unproxied)} DNS-only")
        if leaks:
            # Not a breach, but it publishes your internal addressing to
            # anyone who runs dig. Worth a deliberate decision either way.
            print(f"\n  ⚠️  {len(leaks)} PUBLIC records resolve to PRIVATE addresses —")
            print("      this publishes internal topology to anyone who asks:")
            for r in leaks:
                print(f"        {r['name']:34} -> {r['content']}")
            print("      These are LAN-only services. NetBird already provides")
            print("      remote access to them, so public DNS is not required.")

    # --- zone security settings ----------------------------------------
    ok, d = call(f"/zones/{ZONE}/settings", tok=tok)
    if not ok:
        print(f"\n[SETTINGS]  UNREADABLE — {d}")
        gaps.append("Zone Settings:Read")
    else:
        want = {
            "ssl": ("strict", "full TLS to origin"),
            "min_tls_version": ("1.2", "reject TLS 1.0/1.1"),
            "always_use_https": ("on", "no plaintext"),
            "security_level": (None, "challenge threshold"),
            "browser_check": ("on", "basic bot check"),
        }
        got = {s["id"]: s.get("value") for s in d["result"]}
        print("\n[SETTINGS]")
        for k, (expect, why) in want.items():
            v = got.get(k, "?")
            mark = "  " if (expect is None or str(v) == expect) else "⚠️"
            print(f"  {mark} {k:22} = {v}   ({why})")

    # --- WAF custom rules ----------------------------------------------
    ok, d = call(f"/zones/{ZONE}/rulesets", tok=tok)
    if not ok:
        print(f"\n[WAF]       UNREADABLE — {d}")
        gaps.append("Zone WAF:Read")
    else:
        rs = d["result"]
        for phase, label in (("http_request_firewall_custom", "custom rules"),
                             ("http_ratelimit", "rate limiting")):
            ents = [r for r in rs if r.get("phase") == phase
                    and r.get("kind") == "zone"]
            if not ents:
                print(f"\n[WAF]       {label}: NONE configured")
                continue
            ok2, d2 = call(f"/zones/{ZONE}/rulesets/{ents[0]['id']}", tok=tok)
            rules = d2["result"].get("rules", []) if ok2 else []
            print(f"\n[WAF]       {label}: {len(rules)} rule(s)")
            for r in rules:
                print(f"              [{r.get('action')}] "
                      f"{(r.get('description') or '')[:60]}")
                print(f"                 {r.get('expression','')[:110]}")

    if gaps:
        print("\n" + "-" * 72)
        print("TOKEN TOO NARROW. Could not read: " + ", ".join(gaps))
        print("Mint a token with Zone:Read + Zone Settings:Read + Zone WAF:Read")
        print("(add Zone WAF:Edit to apply rules) and re-run with CF_API_TOKEN set.")
        print("A narrow token reads as 'nothing configured' — it is not the same")
        print("thing, and this script will not pretend otherwise.")
    return 0


# -------------------------------------------------------------- waf rules --
# Each rule matches a hostile PATH or USER AGENT, never a whole hostname.
# Free plan allows 5 custom rules; three are proposed, leaving headroom.
PROPOSED = [
    {
        "description": "warden: block config/secret file probes",
        "action": "block",
        # Anchored on path only. /.well-known/ is untouched (ACME + OIDC
        # discovery live there and breaking them breaks certs and SSO).
        "expression": (
            '(http.request.uri.path contains "/.env") or '
            '(http.request.uri.path contains "/.git/") or '
            '(http.request.uri.path contains "/.aws/") or '
            '(http.request.uri.path contains "/etc/passwd") or '
            '(http.request.uri.path contains "/wp-admin") or '
            '(http.request.uri.path contains "/wp-login") or '
            '(http.request.uri.path contains "/phpmyadmin") or '
            '(http.request.uri.path contains "/adminer") or '
            '(http.request.uri.path contains "/actuator")'
        ),
    },
    {
        "description": "warden: challenge known scanner user agents",
        # managed_challenge, not block: user-agent is trivially spoofed, so a
        # hard block buys little and a false positive would be invisible.
        "action": "managed_challenge",
        "expression": (
            '(lower(http.user_agent) contains "sqlmap") or '
            '(lower(http.user_agent) contains "nikto") or '
            '(lower(http.user_agent) contains "nuclei") or '
            '(lower(http.user_agent) contains "masscan") or '
            '(lower(http.user_agent) contains "zgrab") or '
            '(lower(http.user_agent) contains "dirbuster") or '
            '(lower(http.user_agent) contains "gobuster") or '
            '(lower(http.user_agent) contains "wpscan")'
        ),
    },
    {
        "description": "warden: block obvious SQLi / traversal in query string",
        "action": "block",
        # ⚠️ url_decode() is essential here. `contains` matches the RAW query
        # string, where a space is %20 — so `?id=1 union select 1` arrives as
        # "union%20select" and a plain contains "union select" never fires.
        # The identical bug was caught by the Worker's unit test; the rule
        # below would have looked correct and blocked nothing.
        "expression": (
            '(lower(url_decode(http.request.uri.query)) contains "union select") or '
            '(lower(url_decode(http.request.uri.query)) contains "benchmark(") or '
            '(lower(url_decode(http.request.uri.query)) contains "sleep(") or '
            '(url_decode(http.request.uri.path) contains "../")'
        ),
    },
]


def apply_waf(tok, commit):
    ok, d = call(f"/zones/{ZONE}/rulesets", tok=tok)
    if not ok:
        print(f"cannot list rulesets: {d}")
        print("Needs a Zone WAF:Edit token — see the module docstring.")
        return 2

    ents = [r for r in d["result"]
            if r.get("phase") == "http_request_firewall_custom"
            and r.get("kind") == "zone"]

    existing = []
    rsid = None
    if ents:
        rsid = ents[0]["id"]
        ok2, d2 = call(f"/zones/{ZONE}/rulesets/{rsid}", tok=tok)
        existing = d2["result"].get("rules", []) if ok2 else []

    have = {(r.get("description") or "") for r in existing}
    todo = [r for r in PROPOSED if r["description"] not in have]

    print(f"existing custom rules: {len(existing)}")
    for r in existing:
        print(f"  keep  [{r.get('action')}] {r.get('description','')[:60]}")
    for r in todo:
        print(f"  ADD   [{r['action']}] {r['description']}")
        print(f"          {r['expression'][:100]}...")
    if not todo:
        print("nothing to add — all proposed rules already present")
        return 0

    if not commit:
        print("\nDRY RUN — nothing written. Re-run with --commit to apply.")
        print("Review the expressions above first: a rule that matches a whole")
        print("hostname has broken this estate before (NetBird, 2026-07-03).")
        return 0

    # Rules are replaced as a set, so existing ones must be sent back with the
    # new ones or they are silently deleted.
    body = {"rules": [{"action": r["action"], "expression": r["expression"],
                       "description": r.get("description", ""),
                       "enabled": r.get("enabled", True)}
                      for r in existing]
            + [{**r, "enabled": True} for r in todo]}
    if rsid:
        ok, d = call(f"/zones/{ZONE}/rulesets/{rsid}", "PUT", body, tok)
    else:
        ok, d = call(f"/zones/{ZONE}/rulesets", "POST",
                     {"name": "default", "kind": "zone",
                      "phase": "http_request_firewall_custom", **body}, tok)
    print(("applied: " if ok else "FAILED: ") + (json.dumps(d)[:200] if not ok else
                                                 f"{len(todo)} rule(s) added"))
    return 0 if ok else 1


def main():
    tok = token()
    if not tok:
        print("no CF_API_TOKEN and no readable /etc/caddy/caddy.env", file=sys.stderr)
        return 2
    if "--apply-waf" in sys.argv:
        return apply_waf(tok, "--commit" in sys.argv)
    # The WAF token cannot read DNS and the Caddy token can. Hand the DNS
    # section whichever one is not the primary, so one audit covers both.
    other = _caddy_token() if tok != _caddy_token() else _infisical_token()
    return audit(tok, dns_tok=other or tok)


if __name__ == "__main__":
    sys.exit(main())
