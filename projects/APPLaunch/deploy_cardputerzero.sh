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

DOCKER_IMAGE="${DOCKER_IMAGE:-ubuntu:22.04}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-m5cz_applaunch_builder}"
DOCKER_PERSIST="${DOCKER_PERSIST:-1}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Step 1 — Cross-compile inside Docker (repo mounted at /work)
# ---------------------------------------------------------------------------
echo "==> [1/3] Docker cross-compile APPLaunch for aarch64..."

ensure_docker_builder_container() {
  if [[ "${DOCKER_PERSIST}" != "1" ]]; then
    return 0
  fi

  if ! docker ps -a --format '{{.Names}}' | grep -qx "${DOCKER_CONTAINER}"; then
    echo "    Creating persistent builder container: ${DOCKER_CONTAINER}"
    docker run -d \
      --name "${DOCKER_CONTAINER}" \
      -v "${REPO_ROOT}:/work" \
      -w /work \
      "${DOCKER_IMAGE}" \
      tail -f /dev/null > /dev/null
  elif ! docker ps --format '{{.Names}}' | grep -qx "${DOCKER_CONTAINER}"; then
    docker start "${DOCKER_CONTAINER}" > /dev/null
  fi

  if ! docker exec "${DOCKER_CONTAINER}" test -f /opt/appbuild/.deps_ready; then
    echo "    Installing builder dependencies (first run only)..."
    docker exec "${DOCKER_CONTAINER}" bash -lc "
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq \
        python3 python3-pip g++-aarch64-linux-gnu \
        pkg-config libfreetype6-dev libpng-dev zlib1g-dev > /dev/null
      pip3 install scons parse --quiet
      mkdir -p /opt/appbuild
      touch /opt/appbuild/.deps_ready
    "
  fi
}

if [[ "${DOCKER_PERSIST}" == "1" ]]; then
  ensure_docker_builder_container
  docker exec "${DOCKER_CONTAINER}" bash -lc "
    set -e
    cd /work/projects/APPLaunch
    CONFIG_REPO_AUTOMATION=1 CardputerZero=y python3 -m SCons -j\$(nproc)
  "
else
  docker run --rm \
    -v "${REPO_ROOT}:/work" \
    "${DOCKER_IMAGE}" \
    bash -c "
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq \
        python3 python3-pip g++-aarch64-linux-gnu \
        pkg-config libfreetype6-dev libpng-dev zlib1g-dev > /dev/null
      pip3 install scons parse --quiet
      cd /work/projects/APPLaunch
      CONFIG_REPO_AUTOMATION=1 CardputerZero=y python3 -m SCons -j\$(nproc)
    "
fi

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
