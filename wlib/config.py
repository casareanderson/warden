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
    # vulnerability scanning (vulnscan.py, images.py): advisories from api.osv.dev, nothing to configure
    "vuln": {},
    # public API + MCP
    "api": {"enabled": True, "public_url": ""},     # public_url: how agents reach /mcp (shown in Settings)
    # dashboard server. Binds to localhost: put a reverse proxy with auth in front, or set
    # basic_user + the WARDEN_UI_PASSWORD secret. /api/v1 and /mcp always need a bearer token.
    "ui": {"host": "127.0.0.1", "port": 8792, "basic_user": "", "password_secret": "WARDEN_UI_PASSWORD",
           "trust_proxy_user_header": "Remote-User"},
    # home-page layout; None = the built-in default (see warden-ui.py WIDGETS)
    "dashboard": {"widgets": None},
}

OVERRIDES = DATA / "overrides.yml"   # what the console's Settings editor changed (the UI can't write warden.yml)

# The only keys the console may change, each with its validator. Anything that reaches a machine (ssh targets,
# hosts, IDS host), grants authority (notify.owner_id), or decides bans stays in warden.yml, edited by hand.
# (review 2026-10-09: ids.suricata_host reached ssh argv → -oProxyCommand as root; owner_id = approval authority.)
import re as _re  # noqa: E402

_URL = _re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?(/[^\s\"'<>`]*)?$")
EDITABLE = {
    "estate.name": ("text", _re.compile(r"^[\w .\-]{1,40}$")),
    "estate.domain": ("text", _re.compile(r"^$|^[a-z0-9.\-]{1,253}$")),
    "estate.timezone": ("text", "tz"),
    "notify.backend": (["none", "discord", "webhook", "ntfy"], None),
    "notify.channel": ("text", _re.compile(r"^$|^\d{5,25}$")),
    "notify.ntfy_url": ("text", _re.compile(r"^$|^https://[^\s\"'<>`]+$")),
    "api.enabled": ("bool", None),
    "api.public_url": ("text", _re.compile(r"^$|" + _URL.pattern[1:])),
    "cloudflare.zone_id": ("text", _re.compile(r"^$|^[0-9a-f]{32}$")),
    "patch.night": ("text", _re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")),
    "patch.expire_hours": ("int", (1, 168)),
}

_cache = {"mtime": None, "cfg": None}


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def cfg(reload=False):
    """The merged config. Re-read when the file changes, so a running UI sees edits."""
    def _mt(p):
        try:
            return p.stat().st_mtime
        except OSError:
            return None
    mt = (_mt(CONF), _mt(OVERRIDES))
    if reload or _cache["cfg"] is None or mt != _cache["mtime"]:
        raw, over = {}, {}
        if mt[0] is not None:
            if yaml is None:
                raise RuntimeError("PyYAML is required: apt install python3-yaml (or pip install pyyaml)")
            raw = yaml.safe_load(CONF.read_text()) or {}
        if mt[1] is not None and yaml is not None:
            try:
                over = yaml.safe_load(OVERRIDES.read_text()) or {}
            except (OSError, yaml.YAMLError):
                over = {}
        _cache.update(mtime=mt, cfg=_merge(_merge(DEFAULTS, raw), over))
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


def set_override(key, value):
    """Console edit of one EDITABLE key → data/overrides.yml (warden.yml is never touched by the UI)."""
    if key not in EDITABLE:
        raise KeyError(key)
    kind, rule = EDITABLE[key]
    if value is None:
        raise ValueError("no value given")
    if kind == "bool":
        value = value in (True, "true", "1", 1, "on")
    elif kind == "int":
        value = int(value)
        if not rule[0] <= value <= rule[1]:
            raise ValueError(f"{key} must be between {rule[0]} and {rule[1]}")
    elif isinstance(kind, list):
        if value not in kind:
            raise ValueError(f"{key} must be one of {', '.join(kind)}")
    else:
        value = str(value).strip()
        if rule == "tz":
            from zoneinfo import ZoneInfo  # noqa: PLC0415
            try:
                ZoneInfo(value)
            except Exception:  # noqa: BLE001
                raise ValueError(f"unknown time zone {value!r} (e.g. Europe/London)") from None
        elif not rule.match(value):
            raise ValueError(f"{key}: not a valid value")
    over = {}
    if OVERRIDES.exists():
        over = yaml.safe_load(OVERRIDES.read_text()) or {}
    cur = over
    parts = key.split(".")
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value
    DATA.mkdir(parents=True, exist_ok=True)
    OVERRIDES.write_text(yaml.safe_dump(over, sort_keys=False, allow_unicode=True))
    cfg(reload=True)
    return value
