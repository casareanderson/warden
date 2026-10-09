"""Secrets, resolved at call time and never written to logs.

    secrets.get("CF_API_TOKEN")

Lookup order:
  1. environment variable of that name (spaces/slashes → underscores, upper-cased)
  2. $WARDEN_DATA/secrets.env  (KEY=value lines, chmod 600; written by warden-setup),
     then any files listed in `secrets.files` (e.g. an agent's existing .env)
  3. an optional backend from warden.yml `secrets.backend`:
       env        nothing further (default)
       infisical  `infisical secrets get` via the CLI, folder from `secrets.map`
       command    run `secrets.command` with the name appended; stdout is the value
  `secrets.map` lets a name point somewhere else, e.g.
       secrets: {backend: infisical, map: {CF_API_TOKEN: "/Cloudflare:WAF token"}}
"""
import os
import re
import subprocess

from . import config


def _envname(name):
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()


def _file():
    """data/secrets.env, then any extra KEY=value files listed in `secrets.files` (first one wins)."""
    out = {}
    paths = [config.DATA / "secrets.env"] + [config.Path(p) for p in (config.get("secrets.files") or [])]
    for path in paths:
        try:
            for line in path.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    out.setdefault(k.strip().removeprefix("export ").strip(), v.strip().strip("'\""))
        except OSError:
            pass
    return out


def get(name, default=None):
    key = _envname(name)
    if os.environ.get(key):
        return os.environ[key]
    f = _file()
    if f.get(key):
        return f[key]
    sc = config.get("secrets", {}) or {}
    target = (sc.get("map") or {}).get(name, name)
    backend = sc.get("backend", "env")
    try:
        if backend == "infisical":
            folder, _, secret = target.rpartition(":") if ":" in target else ("/", "", target)
            argv = ["infisical", "secrets", "get", secret, "--path", folder or "/", "--plain", "--silent"]
            if sc.get("project_id"):
                argv += ["--projectId", sc["project_id"]]
            if sc.get("env"):
                argv += ["--env", sc["env"]]
            p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.strip()
        elif backend == "command" and sc.get("command"):
            p = subprocess.run(sc["command"].split() + [target], capture_output=True, text=True, timeout=30)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.strip()
        elif backend == "hermes":                   # the author's own estate: hermes_secrets resolver
            import sys
            sys.path.insert(0, sc.get("hermes_path", "/opt/hermes-agent"))
            import hermes_secrets  # noqa: PLC0415
            folder, _, secret = target.rpartition(":") if ":" in target else ("/", "", target)
            v = hermes_secrets.get(secret, folder)
            if v:
                return v
    except Exception:  # noqa: BLE001 - a broken backend must read as "missing", not crash a scan
        pass
    return default


def have(name):
    return bool(get(name))


SETTABLE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


def put(name, value):
    """Console 'set secret': write KEY=value into data/secrets.env (0600). Never read back to the browser."""
    key = _envname(name)
    if not SETTABLE.match(key) or not value or "\n" in value or len(value) > 4096:
        raise ValueError("bad secret name or value")
    path = config.DATA / "secrets.env"
    lines = []
    try:
        lines = [l for l in path.read_text().splitlines() if not l.split("=", 1)[0].strip() == key]
    except OSError:
        pass
    lines.append(f"{key}={value}")
    config.DATA.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
