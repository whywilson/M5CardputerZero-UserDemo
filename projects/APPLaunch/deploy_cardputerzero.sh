#!/usr/bin/env bash
# ============================================================================
# deploy_cardputerzero.sh — Docker cross-compile APPLaunch for aarch64, then
#                           push to CardputerZero Pi and restart service.
#
# Usage:
#   ./deploy_cardputerzero.sh [host] [user] [password]
#
# Defaults:  host=192.168.0.110  user=pi  pass=pi
# ============================================================================
set -euo pipefail

DEVICE_HOST="${1:-192.168.0.110}"
DEVICE_USER="${2:-pi}"
DEVICE_PASS="${3:-pi}"
REMOTE_STAGE="/home/${DEVICE_USER}/dist"
REMOTE_BIN="/usr/share/APPLaunch/bin"
SERVICE="APPLaunch.service"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Step 1 — Cross-compile inside Docker (repo mounted at /work)
# ---------------------------------------------------------------------------
echo "==> [1/3] Docker cross-compile APPLaunch for aarch64..."

docker run --rm \
  -v "${REPO_ROOT}:/work" \
  ubuntu:22.04 \
  bash -c "
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip g++-aarch64-linux-gnu > /dev/null
    pip3 install scons parse --quiet
    cd /work/projects/APPLaunch
    CONFIG_REPO_AUTOMATION=1 CardputerZero=y python3 -m SCons -j\$(nproc)
  "

echo "==> [1/3] Built: ${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch"
ls -lh "${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch"

# ---------------------------------------------------------------------------
# Step 2 — Deploy binary to device
# ---------------------------------------------------------------------------
echo ""
echo "==> [2/3] Deploying to ${DEVICE_USER}@${DEVICE_HOST}..."

if command -v sshpass >/dev/null 2>&1; then
  _SSH() { sshpass -p "${DEVICE_PASS}" ssh -o StrictHostKeyChecking=no "$@"; }
  _SCP() { sshpass -p "${DEVICE_PASS}" scp -o StrictHostKeyChecking=no "$@"; }
else
  echo "    (sshpass not found — install via 'brew install sshpass')"
  _SSH() { ssh "$@"; }
  _SCP() { scp "$@"; }
fi

_SSH "${DEVICE_USER}@${DEVICE_HOST}" "mkdir -p '${REMOTE_STAGE}'"
_SCP "${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch" \
     "${DEVICE_USER}@${DEVICE_HOST}:${REMOTE_STAGE}/M5CardputerZero-APPLaunch"

# ---------------------------------------------------------------------------
# Step 3 — Install and restart service
# ---------------------------------------------------------------------------
echo ""
echo "==> [3/3] Installing and restarting ${SERVICE}..."

_SSH "${DEVICE_USER}@${DEVICE_HOST}" "
  echo '${DEVICE_PASS}' | sudo -S systemctl stop  ${SERVICE}
  echo '${DEVICE_PASS}' | sudo -S cp '${REMOTE_STAGE}/M5CardputerZero-APPLaunch' '${REMOTE_BIN}'
  echo '${DEVICE_PASS}' | sudo -S systemctl start ${SERVICE}
  sleep 2
  systemctl is-active ${SERVICE}
"

echo ""
echo "==> Done. APPLaunch restarted on ${DEVICE_HOST}."
