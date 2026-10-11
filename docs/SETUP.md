# Setting up warden

Two ways in: a **five-minute look** with demo data (nothing to wire up), then the **real install** on your own
estate. The blocks marked as tested below run on a fresh Ubuntu runner every week in
[`setup-check`](../.github/workflows/setup-check.yml). The real install needs your machines, logs and accounts,
so CI can't prove those steps; they're the ones without a test mark.

## What you need

- Linux with systemd and Python 3. Tested on Ubuntu 24.04 (Python 3.12) and Debian 13 (Python 3.13), x86_64.
- Packages: `python3-yaml`, `python3-requests`, and `nmap` for LAN discovery.
- About 512 MB RAM and 300 MB disk for the core; 1.5 GB RAM and 2.5 GB disk if you turn on vulnerability
  scanning (see [Minimum spec](../README.md#minimum-spec)).
- For the real install: SSH keys to the machines you want scanned (nothing gets installed on them), and a reverse
  proxy with HTTPS in front of the console.

## Get it

```sh setup-check
sudo apt-get update -qq
sudo apt-get install -y -qq python3-yaml python3-requests nmap
sudo git clone -q https://github.com/casareanderson/warden.git /opt/warden
sudo chown -R "$USER" /opt/warden
cd /opt/warden
```

## The five-minute look (demo data)

This fills a throwaway database with made-up detections, devices and CVEs, so you can click round the console
before you point it at anything real.

```sh setup-check
export WARDEN_DATA=/tmp/warden-demo
python3 tools/demo.py
./warden-setup user add demo --role admin
```

You should see `demo data written to /tmp/warden-demo/warden.db`, then a one-time password for `demo`. Start the
console:

```
python3 warden-ui.py
```

Open http://127.0.0.1:8792, sign in as `demo` with that password, and pick your own password when it asks.

### Check it from the command line

The console has a REST API and an MCP endpoint for AI agents, both behind a bearer token. Mint one and ask
for the summary:

```sh setup-check
TOKEN=$(./warden-setup token try-it | head -1)
python3 warden-ui.py > /tmp/warden-ui.log 2>&1 &
UI=$!
sleep 3
curl -fsS -o /dev/null -w "%{http_code} %{redirect_url}\n" http://127.0.0.1:8792/ || true
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8792/api/v1/summary | python3 -m json.tool | head -20
curl -fsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:8792/mcp | python3 -c \
  "import json,sys; print([t['name'] for t in json.load(sys.stdin)['result']['tools']])"
kill $UI
```

The home page answers `302` to `/login` (the console has its own sign-in), `/api/v1/summary` returns JSON with
`"mode": "detect-only"` and the headline counts, and the MCP call lists the tools, starting with
`warden_summary`. Without the token the API answers `401`.

When you're done looking: `rm -rf /tmp/warden-demo`.

## The real install

Not tested in CI from here on: these steps ask you questions and talk to your own machines.

### 1. Write `warden.yml`

```
cd /opt/warden
./warden-setup init
```

It asks about your estate (name, public domain, LAN ranges, timezone), where alerts go, which machines to watch
and whether you use Cloudflare, then writes `warden.yml` (an old copy is kept as `warden.yml.bak`). Every key is
documented in [warden.yml.example](../warden.yml.example). If you'd rather edit by hand:

```sh setup-check
cp warden.yml.example /tmp/warden-check.yml
WARDEN_CONF=/tmp/warden-check.yml ./warden-setup check || echo "check exit code $?"
WARDEN_CONF=/tmp/warden-check.yml ./warden-setup units
```

That tested block only proves the example file loads and the checks run; your own file goes at
`/opt/warden/warden.yml`. `check` exits `1` while anything required is still ✗, and with the untouched example
it is: the example sends alerts to Discord, so it wants a `DISCORD_BOT_TOKEN` (`✗ Alerts via discord`). On your
real install, a `0` from `check` means every required line is ✓, which makes it a handy line for a script.

Secrets never go in `warden.yml`, only their names. Store a value with:

```
./warden-setup secret CLOUDFLARE_API_TOKEN     # prompted, never echoed, saved to data/secrets.env (mode 600)
```

Values can also come from the environment, Infisical or a command (`secrets:` section).

### 2. Ask the running system what works

```
./warden-setup check --hosts
```

Each line is ✓ (working), ✗ (required and missing, with what to do) or ○ (optional and off). `--hosts` also tries
to reach every machine over SSH. Fix the ✗ lines before going on. On a fresh box you'll typically see:

```
 ✗ Config file                          /opt/warden/warden.yml
     → run `warden-setup init` (or copy warden.yml.example to warden.yml)
 ✓ PyYAML installed
 ✓ Database writable                    /opt/warden/data/warden.db
 ○ Alerts go somewhere                  notify.backend is none — alerts only reach the log
 ✓ Vulnerability advisories (api.osv.dev reachable) https://api.osv.dev
 ✓ LAN scanner (nmap)
```

To add one machine later and have it tested before it's saved: `./warden-setup add-host`.

### 3. Turn on the timers

```
./warden-setup units             # shows which units it would enable, and why
sudo ./warden-setup units --install
```

Only the features your config uses are switched on: the core (`warden`, `warden-ui`, `warden-siemalert`,
`warden-geo`) always, LAN scanning when `nmap` is installed, vulnerability scanning and integrity checks once
you've declared a host, patching for hosts with `patch: true`, and the Cloudflare, IDS and router units only
when those sections are filled in. Use `--python PATH` if your Python isn't `/usr/bin/python3`.

### 4. Make yourself an admin

```
./warden-setup user add YOUR-NAME --role admin
```

It prints a one-time password; you choose your own at first sign-in. Roles are `viewer`, `approver` and `admin`.
If your reverse proxy already signs people in (Authelia, Authentik, oauth2-proxy), set `ui.auth: proxy` instead.

### 5. Put HTTPS in front of the console

The console binds to `127.0.0.1:8792`. Point your reverse proxy (Caddy, NGINX, NPMplus, Traefik) at it. If the
proxy has its own login page, let `/mcp` and `/api/v1` straight through: an MCP client can't follow a login
redirect, and the bearer token is the auth on those two paths.

### 6. Connect your AI agent (optional)

```
./warden-setup token hermes      # shown once; warden keeps only the hash
./warden-setup connect           # prints ready-to-paste Hermes, Claude Code and curl snippets
```

Every MCP tool is read-only, and a test enforces it: nothing an agent calls can ban, block, patch or approve.

## Environment variables

You don't need any of these for a normal install under `/opt/warden`:

| variable | default | what it does |
|---|---|---|
| `WARDEN_HOME` | the checkout directory | where warden lives |
| `WARDEN_CONF` | `$WARDEN_HOME/warden.yml` | config file |
| `WARDEN_DATA` | `$WARDEN_HOME/data` | database, secrets file, caches |
| `WARDEN_GEO_DB` | `$WARDEN_DATA/geo.db` | IP geolocation database |
| `WARDEN_UI_HOST` / `WARDEN_UI_PORT` | `127.0.0.1` / `8792` | where the console listens |
| `WARDEN_UI_PASSWORD` | unset | default secret name for a console password (`ui.password_secret`) |
| `WARDEN_LOG_HOST` | unset | SSH target for logs, if not set in `sources:` |

## Common problems

| you see | what it means | what to do |
|---|---|---|
| `✗ Config file` in `check` | no `warden.yml` yet | `./warden-setup init`, or copy the example |
| `○ Alerts go somewhere … notify.backend is none` | alerts only reach the log | set `notify.backend` to `discord`, `webhook` or `ntfy` |
| `○ IP geolocation database` | not downloaded yet | it fills on the first `warden-geo` timer run |
| `401` from `/api/v1/...` or `/mcp` | missing or revoked token | `./warden-setup tokens`, mint a new one |
| a source that was busy suddenly reads 0 lines | the SSH to the log host broke; it looks the same as a quiet night | check the Health page and the SSH key (see [KNOWN-ISSUES.md](../KNOWN-ISSUES.md)) |
| the agent gets a login page instead of JSON | the proxy's login is in front of `/mcp` or `/api/v1` | let those two paths through |
| you thought you'd blocked an attacker | warden is detect-only by default | that's on purpose; read KNOWN-ISSUES.md before `enforce: true` |

## Update

```
cd /opt/warden
git pull
sudo ./warden-setup units --install    # picks up new or changed units
./warden-setup check
```

Your `warden.yml`, `data/` (database, secrets, layout) and users stay as they are.

## Uninstall

```
cd /opt/warden
./warden-setup units                   # lists the unit names
sudo systemctl disable --now 'warden*.timer' 'warden*.service'
sudo rm /etc/systemd/system/warden*.service /etc/systemd/system/warden*.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/warden                # this deletes data/ too: database, secrets.env, users
```

Nothing was installed on the machines warden watched, so there's nothing to clean up on them. Revoke any SSH
keys and Cloudflare tokens you made for it.
