#!/usr/bin/env python3
"""Deploy edge-sentry to Cloudflare Workers — without wrangler or npm.

Why not wrangler: it wants a Node toolchain and a global install on a
container that has neither, and it hides what is actually sent. This does the
same three API calls directly, which also makes the required token scopes
obvious when one is missing.

Scopes needed (verified present on the Infisical `WAF token` 2026-09-21):
  Account -> Workers Scripts:Edit   (upload the script)
  Zone    -> Workers Routes:Edit    (attach it to hostnames)
Note that listing /accounts needs a SEPARATE permission this token lacks, so
a 200-with-empty-result there is NOT evidence of missing Workers access —
that false negative cost a wrong conclusion once already. The account id is
read from the zone record instead.

Order matters: upload the script FIRST, then attach routes. A route pointing
at a script that does not exist yet is rejected, and a half-applied deploy
that leaves routes without a script would 500 every request on those
hostnames.
"""
import os
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, "/opt/hermes-agent")

API = "https://api.cloudflare.com/client/v4"
ZONE = ""
SCRIPT = "edge-sentry"
# The hostnames the Worker should sit in front of. Yours, not these.
HOSTS = os.environ.get("EDGE_HOSTS", "auth,photos,vpn,app").split(",")
HERE = Path(__file__).resolve().parent


def secret(key, path):
    import hermes_secrets
    return (hermes_secrets.get(key, path) or "").strip()


def req(method, path, tok, data=None, ctype="application/json"):
    r = urllib.request.Request(
        API + path, method=method, data=data,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return True, json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            return False, json.load(e)
        except Exception:
            return False, {"errors": [{"message": f"HTTP {e.code}"}]}
    except Exception as e:
        return False, {"errors": [{"message": str(e)[:150]}]}


def err(d):
    return (d.get("errors") or [{}])[0].get("message", "?")


def upload(tok, acct, webhook, self_ips):
    """Multipart upload of an ES-module Worker.

    Secrets go in as `secret_text` bindings rather than being baked into the
    script body, so the webhook URL never appears in the source and is not
    readable back out of the deployed script.
    """
    body = (HERE / "worker.js").read_text()
    meta = {
        "main_module": "worker.js",
        "compatibility_date": "2026-09-01",
        "bindings": [
            {"type": "secret_text", "name": "ALERT_WEBHOOK", "text": webhook},
            {"type": "secret_text", "name": "SELF_IPS", "text": self_ips},
        ],
    }
    b = f"----{uuid.uuid4().hex}"
    parts = []
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="metadata"\r\n'
                 f'Content-Type: application/json\r\n\r\n{json.dumps(meta)}\r\n')
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="worker.js"; '
                 f'filename="worker.js"\r\n'
                 f'Content-Type: application/javascript+module\r\n\r\n{body}\r\n')
    parts.append(f"--{b}--\r\n")
    payload = "".join(parts).encode("utf-8")
    return req("PUT", f"/accounts/{acct}/workers/scripts/{SCRIPT}", tok,
               payload, f"multipart/form-data; boundary={b}")


def main():
    tok = secret("WAF token", "/Cloudflare")
    if not tok:
        print("no Cloudflare token in Infisical /Cloudflare", file=sys.stderr)
        return 2

    # Webhook: Infisical first, then argv, so nothing secret lands in shell
    # history or a process listing when it can be avoided.
    webhook = secret("EDGE_WEBHOOK", "/Cloudflare")
    if not webhook and len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        webhook = sys.argv[1].strip()
    if not webhook:
        print("no EDGE_WEBHOOK in Infisical /Cloudflare and none passed.",
              file=sys.stderr)
        print("The Worker's only job is reporting; deploying it without a "
              "destination puts code in the request path of six hostnames "
              "for no benefit. Refusing.", file=sys.stderr)
        return 2

    self_ips = ",".join(
        l.split("#")[0].strip()
        for l in (Path("/opt/warden/self-ips.txt").read_text().splitlines()
                  if Path("/opt/warden/self-ips.txt").exists() else [])
        if l.split("#")[0].strip() and ":" not in l.split("#")[0])

    ok, d = req("GET", f"/zones/{ZONE}", tok)
    if not ok:
        print("cannot read zone:", err(d)); return 1
    acct = d["result"]["account"]["id"]
    print(f"account {acct}")

    ok, d = upload(tok, acct, webhook, self_ips)
    if not ok:
        print("UPLOAD FAILED:", err(d)); return 1
    print(f"uploaded {SCRIPT} (self_ips={self_ips or 'none'})")

    ok, d = req("GET", f"/zones/{ZONE}/workers/routes", tok)
    existing = {r["pattern"]: r["id"] for r in d.get("result", [])} if ok else {}

    for h in HOSTS:
        pat = f"{h}.example.com/*"
        if pat in existing:
            print(f"  route exists  {pat}")
            continue
        ok, d = req("POST", f"/zones/{ZONE}/workers/routes", tok,
                    json.dumps({"pattern": pat, "script": SCRIPT}).encode())
        print(f"  route {'added   ' if ok else 'FAILED  '} {pat}"
              f"{'' if ok else '  ' + err(d)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
