"""Secrets, resolved at call time and never written to logs.

    secrets.get("CF_API_TOKEN")

Lookup order:
  1. environment variable of that name (spaces/slashes → underscores, upper-cased)
  2. $WARDEN_DATA/secrets.env  (KEY=value lines, chmod 600; written by warden-setup)
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
    out = {}
    try:
        for line in (config.DATA / "secrets.env").read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
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
