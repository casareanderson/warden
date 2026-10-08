#!/usr/bin/env python3
"""bringup — wait for the bot to gain Manage Webhooks, then create the
alert-channel webhook (notify.channel in warden.yml) and deploy edge-sentry
in the same process. Needs the Discord bot token (notify.token_secret).

Doing it in one process is deliberate: the webhook URL is a credential, and
passing it between steps would put it in a command line (visible in `ps`) or
in shell history. Here it exists only in memory and in the Cloudflare secret
binding.

Idempotent. Re-running reuses an existing `edge-sentry` webhook rather than
creating a second one, and deploy.py skips routes that already exist.
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import requests                                    # noqa: E402
import deploy as D                                 # noqa: E402
from wlib import config, notify, secrets           # noqa: E402

CHANNEL = notify.channel()
POLL_SECONDS = 15
MAX_WAIT = int(sys.argv[1]) if len(sys.argv) > 1 else 600


def main():
    tok = secrets.get(config.get("notify.token_secret") or "DISCORD_BOT_TOKEN")
    if not tok or not CHANNEL:
        print("needs notify.channel and a Discord bot token (DISCORD_BOT_TOKEN)", file=sys.stderr)
        return 2
    h = {"Authorization": "Bot " + tok}
    base = f"https://discord.com/api/v10/channels/{CHANNEL}/webhooks"

    waited = 0
    while True:
        r = requests.get(base, headers=h, timeout=20)
        if r.status_code == 200:
            break
        if r.status_code != 403:
            print(f"unexpected {r.status_code}: {r.text[:160]}", file=sys.stderr)
            return 1
        if waited >= MAX_WAIT:
            print(f"still no Manage Webhooks after {waited}s — grant it on the "
                  f"bot's role (or as a channel override) and re-run.",
                  file=sys.stderr)
            return 2
        time.sleep(POLL_SECONDS)
        waited += POLL_SECONDS

    print(f"Manage Webhooks granted (waited {waited}s)")

    hooks = r.json()
    hook = next((w for w in hooks if w.get("name") == "edge-sentry"), None)
    if hook:
        print(f"reusing existing webhook {hook['id']}")
    else:
        c = requests.post(base, headers=h, json={"name": "edge-sentry"}, timeout=20)
        if c.status_code not in (200, 201):
            print(f"webhook create failed {c.status_code}: {c.text[:160]}",
                  file=sys.stderr)
            return 1
        hook = c.json()
        print(f"created webhook {hook['id']}")

    url = f"https://discord.com/api/webhooks/{hook['id']}/{hook['token']}"

    # Hand it straight to the deploy path in-process. deploy.main() reads the
    # secret store first, so shim the lookup rather than putting the URL on argv.
    orig = D.secret

    def patched(key, path=None):
        if key == "EDGE_WEBHOOK":
            return url
        return orig(key, path)

    D.secret = patched
    rc = D.main()
    D.secret = orig
    return rc


if __name__ == "__main__":
    sys.exit(main())
