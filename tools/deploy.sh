#!/usr/bin/env bash
# Safe in-place deploy of the working tree to a live warden install.
#   tools/deploy.sh [/opt/warden]
# NEVER touches live config, secrets, data or local backups. Always backs up warden.yml first.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:-/opt/warden}"
[ -d "$DST" ] || { echo "no such install: $DST" >&2; exit 1; }
ts="$(date +%Y%m%d-%H%M%S)"
# back up the live config before anything
[ -f "$DST/warden.yml" ] && cp -p "$DST/warden.yml" "$DST/warden.yml.bak-deploy-$ts"
rsync -a --delete \
  --exclude='.git' \
  --exclude='data' \
  --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='warden.yml' \
  --exclude='secrets.env' --exclude='.env' \
  --exclude='*.bak*' \
  "$SRC"/ "$DST"/
echo "deployed $SRC -> $DST (config/data/secrets preserved; warden.yml backed up as warden.yml.bak-deploy-$ts)"
echo "restart the UI with: systemctl restart warden-ui.service"
