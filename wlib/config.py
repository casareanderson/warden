"""One place that knows where warden lives and what it was told.

WARDEN_HOME   install dir (default: the directory above this package)
WARDEN_CONF   config file (default: $WARDEN_HOME/warden.yml)

Every module reads settings through `cfg()` / `get("a.b.c")` instead of
module-level constants, so a new estate is a config edit, not a code edit.
"""
import os
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - checked by `warden-setup check`
    yaml = None

HOME = Path(os.environ.get("WARDEN_HOME") or Path(__file__).resolve().parent.parent)
CONF = Path(os.environ.get("WARDEN_CONF") or HOME / "warden.yml")
DATA = Path(os.environ.get("WARDEN_DATA") or HOME / "data")
DB = str(DATA / "warden.db")

DEFAULTS = {
    # detection / scoring (warden.py)
    "enforce": False, "ban_threshold": 12, "max_bans_per_run": 3, "window_minutes": 60,
    "allow": [], "ban_hours": 24, "subnet_threshold": 20, "subnet_min_ips": 3,
    # who you are
    "estate": {"name": "home", "domain": "", "timezone": "Europe/London", "lan": [],
               "self_target": ""},          # target id of the box warden runs on (never patched blind)
    # how to reach machines (see wlib/hosts.py)
    "hosts": [],
    # where alerts and approval prompts go (see wlib/notify.py)
    "notify": {"backend": "none"},
    # where secrets come from (see wlib/secrets.py)
    "secrets": {"backend": "env"},
    # log sources for warden.py / siemalert.py
    "sources": {},
    # Cloudflare (cfsec, intel, edgeban) — optional
    "cloudflare": {"zone_id": "", "token_secret": "CF_API_TOKEN", "edge_hosts": [], "sso_exempt": {}},
    # optional extras: network IDS, router, patch window
    "ids": {"suricata_host": "", "eve_path": "/var/log/suricata/eve.json"},
    "router": {"ssh": "", "key": ""},
    "patch": {"night": "02:30", "expire_hours": 24, "snapshot_keep_days": 7,
              "log": "/var/log/warden-patcher.log",
              "advisor": "", "advisor_path": "",     # optional python module with choose(); rule-based without it
              "busy_probe": None},                  # optional {target, json_file, key}: "who is busy" fact for timing
    # vulnerability scanning (vulnscan.py, images.py): trivy in server mode for docker images
    "vuln": {"trivy": "/usr/local/bin/trivy", "cache": "/var/cache/trivy",
             "server": "http://127.0.0.1:4954", "token_file": "/etc/trivy/token"},
    # public API + MCP
    "api": {"enabled": True, "public_url": ""},     # public_url: how agents reach /mcp (shown in Settings)
    # dashboard server. Binds to localhost: put a reverse proxy with auth in front, or set
    # basic_user + the WARDEN_UI_PASSWORD secret. /api/v1 and /mcp always need a bearer token.
    "ui": {"host": "127.0.0.1", "port": 8792, "basic_user": "", "password_secret": "WARDEN_UI_PASSWORD",
           "trust_proxy_user_header": "Remote-User"},
    # home-page layout; None = the built-in default (see warden-ui.py WIDGETS)
    "dashboard": {"widgets": None},
}

_cache = {"mtime": None, "cfg": None}


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def cfg(reload=False):
    """The merged config. Re-read when the file changes, so a running UI sees edits."""
    try:
        mt = CONF.stat().st_mtime
    except OSError:
        mt = None
    if reload or _cache["cfg"] is None or mt != _cache["mtime"]:
        raw = {}
        if mt is not None:
            if yaml is None:
                raise RuntimeError("PyYAML is required: apt install python3-yaml (or pip install pyyaml)")
            raw = yaml.safe_load(CONF.read_text()) or {}
        _cache.update(mtime=mt, cfg=_merge(DEFAULTS, raw))
    return _cache["cfg"]


def get(path, default=None):
    cur = cfg()
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return default if cur is None else cur


def save(new):
    """Write the config back (used by the setup wizard and the dashboard editor).
    The old file is kept as warden.yml.bak so a bad save is one `mv` away."""
    if CONF.exists():
        CONF.with_suffix(CONF.suffix + ".bak").write_text(CONF.read_text())
    CONF.write_text(yaml.safe_dump(new, sort_keys=False, allow_unicode=True))
    cfg(reload=True)


def raw():
    """The file as written (no defaults merged) — what save() should round-trip."""
    if not CONF.exists():
        return {}
    return yaml.safe_load(CONF.read_text()) or {}
