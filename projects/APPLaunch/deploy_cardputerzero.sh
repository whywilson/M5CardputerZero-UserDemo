#!/usr/bin/env bash
# ============================================================================
# deploy_cardputerzero.sh — Local cross-compile APPLaunch, then SCP to device
#                           and restart APPLaunch.service.
#
# Usage:
#   ./deploy_cardputerzero.sh [host] [user] [password]
#
# Defaults: host=192.168.20.113 user=pi pass=pi
# Env:
#   SKIP_BUILD=1          Skip local build
#   BUILD_JOBS=8          Override parallel jobs
#   CONFIG_DEFAULT_FILE   Override scons config defaults
# ============================================================================
set -euo pipefail

DEVICE_HOST="${1:-192.168.20.113}"
DEVICE_USER="${2:-pi}"
DEVICE_PASS="${3:-pi}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SERVICE="APPLaunch.service"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REMOTE_STAGE="/home/${DEVICE_USER}/dist"
REMOTE_APP_ROOT="/usr/share/APPLaunch"
REMOTE_BIN_DIR="${REMOTE_APP_ROOT}/bin"
RFID_ROOT="${REPO_ROOT}/projects/RFID"
RFID_BIN="${RFID_ROOT}/dist/M5CardputerZero-RFID"
RFID_DESKTOP="${RFID_ROOT}/applications/rfid.desktop"
RFID_ICON="${RFID_ROOT}/share/images/ic-rfid.png"
MFKEY_SRC="${RFID_ROOT}/mfkey32v2"
MFKEY_DIST="${RFID_ROOT}/dist_mfkey"

detect_jobs() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    echo 4
  fi
}

BUILD_JOBS="${BUILD_JOBS:-$(detect_jobs)}"

if [[ -z "${CONFIG_DEFAULT_FILE:-}" ]]; then
  case "$(uname -s)" in
    Darwin) export CONFIG_DEFAULT_FILE="mac_cross_cp0_config_defaults.mk" ;;
    *)      export CONFIG_DEFAULT_FILE="linux_x86_cross_cp0_config_defaults.mk" ;;
  esac
fi

# Avoid hidden environment overrides from previous shells.
unset CardputerZero || true

if [[ "${CONFIG_DEFAULT_FILE}" == *"mac_cross_cp0_config_defaults.mk"* ]] && [[ -z "${CONFIG_TOOLCHAIN_PATH:-}" ]]; then
  export CONFIG_TOOLCHAIN_PATH="/opt/homebrew/bin"
fi

if command -v scons >/dev/null 2>&1; then
  SCONS_CMD=(scons)
else
  SCONS_CMD=(python3 -m SCons)
fi

if command -v sshpass >/dev/null 2>&1; then
  _SSH() { sshpass -p "${DEVICE_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"; }
  _SCP() { sshpass -p "${DEVICE_PASS}" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"; }
else
  echo "[WARN] sshpass not found, switching to interactive ssh/scp"
  _SSH() { ssh "$@"; }
  _SCP() { scp "$@"; }
fi

cd "${SCRIPT_DIR}"

# ---------------------------------------------------------------------------
# Step 1 — Local cross build
# ---------------------------------------------------------------------------
if [[ "${SKIP_BUILD}" != "1" ]]; then
  echo "==> [1/3] Local cross-compile APPLaunch (CONFIG_DEFAULT_FILE=${CONFIG_DEFAULT_FILE}, -j${BUILD_JOBS})"
  rm -f "${SCRIPT_DIR}/build/config/global_config.mk" "${SCRIPT_DIR}/build/config/global_config.h"
  "${SCONS_CMD[@]}" -j"${BUILD_JOBS}"
else
  echo "==> [1/3] Skip local build (SKIP_BUILD=1)"
fi

if [[ ! -f "${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch" ]]; then
  echo "[ERROR] Missing build artifact: ${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch"
  exit 1
fi

echo "==> Built artifact: ${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch"
ls -lh "${SCRIPT_DIR}/dist/M5CardputerZero-APPLaunch"

# ---------------------------------------------------------------------------
# Step 1b — Cross-compile mfkey tools if not already built
# ---------------------------------------------------------------------------
if [[ ! -f "${MFKEY_DIST}/mfkey32v2" || ! -f "${MFKEY_DIST}/mfkey64" ]]; then
  echo "==> [1b] Cross-compile mfkey tools for aarch64"
  mkdir -p "${MFKEY_DIST}"
  _MFKEY_CC=""
  for c in "${CONFIG_TOOLCHAIN_PATH:-/opt/homebrew/bin}/aarch64-unknown-linux-gnu-gcc" \
            aarch64-linux-gnu-gcc aarch64-unknown-linux-gnu-gcc; do
    if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then
      _MFKEY_CC="$c"; break
    fi
  done
  if [[ -z "${_MFKEY_CC}" ]]; then
    echo "[WARN] No aarch64 cross-compiler found, skipping mfkey build"
  else
    MFKEY_SRCS="${MFKEY_SRC}/crapto1/crapto1.c ${MFKEY_SRC}/crapto1/crypto1.c ${MFKEY_SRC}/crapto1/bucketsort.c ${MFKEY_SRC}/util_posix.c"
    "${_MFKEY_CC}" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey32v2" \
      "${MFKEY_SRC}/mfkey32v2.c" ${MFKEY_SRCS} -lm -static \
      && echo "    built mfkey32v2" \
      || echo "[WARN] mfkey32v2 build failed"
    "${_MFKEY_CC}" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey64" \
      "${MFKEY_SRC}/mfkey64.c" ${MFKEY_SRCS} -lm -static \
      && echo "    built mfkey64" \
      || echo "[WARN] mfkey64 build failed"
  fi
else
  echo "==> [1b] mfkey tools already built, skipping"
fi

# ---------------------------------------------------------------------------
# Step 2 — SCP stage to device
# ---------------------------------------------------------------------------
echo
echo "==> [2/3] Upload dist -> ${DEVICE_USER}@${DEVICE_HOST}:${REMOTE_STAGE}"
_SSH "${DEVICE_USER}@${DEVICE_HOST}" "mkdir -p '${REMOTE_STAGE}'"
_SCP -r "${SCRIPT_DIR}/dist/." "${DEVICE_USER}@${DEVICE_HOST}:${REMOTE_STAGE}/"

if [[ -f "${RFID_BIN}" && -f "${RFID_DESKTOP}" && -f "${RFID_ICON}" ]]; then
  echo "    + include RFID package files"
  _SCP "${RFID_BIN}" "${RFID_DESKTOP}" "${RFID_ICON}" "${DEVICE_USER}@${DEVICE_HOST}:${REMOTE_STAGE}/"
else
  echo "    - RFID package files not found locally, skip RFID deploy"
fi

if [[ -f "${MFKEY_DIST}/mfkey32v2" && -f "${MFKEY_DIST}/mfkey64" ]]; then
  echo "    + include mfkey tools"
  _SCP "${MFKEY_DIST}/mfkey32v2" "${MFKEY_DIST}/mfkey64" "${DEVICE_USER}@${DEVICE_HOST}:${REMOTE_STAGE}/"
else
  echo "    - mfkey tools not found, skip mfkey deploy"
fi

# ---------------------------------------------------------------------------
# Step 3 — Install and restart service
# ---------------------------------------------------------------------------
echo
echo "==> [3/3] Install files and restart ${SERVICE}"
_SSH "${DEVICE_USER}@${DEVICE_HOST}" "
  set -e
  echo '${DEVICE_PASS}' | sudo -S systemctl stop '${SERVICE}'
  echo '${DEVICE_PASS}' | sudo -S mkdir -p '${REMOTE_BIN_DIR}' '${REMOTE_APP_ROOT}'
  echo '${DEVICE_PASS}' | sudo -S install -m 755 '${REMOTE_STAGE}/M5CardputerZero-APPLaunch' '${REMOTE_BIN_DIR}/M5CardputerZero-APPLaunch'
  if [ -d '${REMOTE_STAGE}/APPLaunch' ]; then
    echo '${DEVICE_PASS}' | sudo -S cp -a '${REMOTE_STAGE}/APPLaunch/.' '${REMOTE_APP_ROOT}/'
  fi
  if [ -f '${REMOTE_STAGE}/store_cache_sync.py' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 644 '${REMOTE_STAGE}/store_cache_sync.py' '${REMOTE_BIN_DIR}/store_cache_sync.py'
  fi
  if [ -f '${REMOTE_STAGE}/M5CardputerZero-RFID' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 755 '${REMOTE_STAGE}/M5CardputerZero-RFID' '${REMOTE_BIN_DIR}/M5CardputerZero-RFID'
  fi
  if [ -f '${REMOTE_STAGE}/rfid.desktop' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 644 '${REMOTE_STAGE}/rfid.desktop' '${REMOTE_APP_ROOT}/applications/rfid.desktop'
  fi
  if [ -f '${REMOTE_STAGE}/ic-rfid.png' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 644 '${REMOTE_STAGE}/ic-rfid.png' '${REMOTE_APP_ROOT}/share/images/ic-rfid.png'
  fi
  if [ -f '${REMOTE_STAGE}/mfkey32v2' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 755 '${REMOTE_STAGE}/mfkey32v2' '${REMOTE_BIN_DIR}/mfkey32v2'
  fi
  if [ -f '${REMOTE_STAGE}/mfkey64' ]; then
    echo '${DEVICE_PASS}' | sudo -S install -m 755 '${REMOTE_STAGE}/mfkey64' '${REMOTE_BIN_DIR}/mfkey64'
  fi
  echo '${DEVICE_PASS}' | sudo -S systemctl start '${SERVICE}'
  sleep 1
  systemctl is-active '${SERVICE}'
"

echo
echo "==> Done. APPLaunch deployed to ${DEVICE_HOST}."
