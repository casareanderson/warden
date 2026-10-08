#!/usr/bin/env python3
"""Redeploy edge-sentry with self-IP suppression on or off.

Used to prove end-to-end alert delivery: every probe this estate can make
originates from its own WAN address, which the Worker suppresses by design.
Turning suppression off briefly is the only way to see a real alert arrive.

⚠️ ALWAYS run `selftest.py on` afterwards. Leaving suppression off means every
photo-app thumbnail 404 from the owner's phone pages the channel — which is the
exact false-alarm problem this whole subsystem was built to remove.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import requests                         # noqa: E402
import deploy as D                      # noqa: E402
from wlib import config, notify, secrets  # noqa: E402

CHANNEL = notify.channel()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "on"
    tok = D.secret(D.WAF)

    ok, d = D.req("GET", f"/zones/{D.ZONE}", tok)
    if not ok:
        print("cannot read zone", d)
        return 1
    acct = d["result"]["account"]["id"]

    h = {"Authorization": "Bot " + (secrets.get(config.get("notify.token_secret") or "DISCORD_BOT_TOKEN") or "")}
    hooks = requests.get(
        f"https://discord.com/api/v10/channels/{CHANNEL}/webhooks",
        headers=h, timeout=20).json()
    hook = next(x for x in hooks if x.get("name") == "edge-sentry")
    url = f"https://discord.com/api/webhooks/{hook['id']}/{hook['token']}"

    if mode == "off":
        self_ips = ""
    else:
        raw = D.SELF_IPS.read_text().splitlines()
        self_ips = ",".join(
            l.split("#")[0].strip() for l in raw
            if l.split("#")[0].strip() and ":" not in l.split("#")[0])

    ok, d = D.upload(tok, acct, url, self_ips)
    print(f"redeployed  suppression={mode}  self_ips={self_ips or 'NONE'}  "
          + ("OK" if ok else f"FAILED {D.err(d)}"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
