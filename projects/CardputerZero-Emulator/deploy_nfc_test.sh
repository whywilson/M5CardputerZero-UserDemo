#!/usr/bin/env bash
# ============================================================================
# deploy_nfc_test.sh — Docker cross-compile nfc-usb-test for aarch64, then
#                      push to CardputerZero Pi via scp.
#
# Usage:
#   ./deploy_nfc_test.sh [host] [user] [password]
#
# Defaults:  host=192.168.0.110  user=pi  pass=pi
# ============================================================================
set -euo pipefail

DEVICE_HOST="${1:-192.168.0.110}"
DEVICE_USER="${2:-pi}"
DEVICE_PASS="${3:-pi}"
DEPLOY_PATH="/home/${DEVICE_USER}/nfc-test"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/build-pi"

# ---------------------------------------------------------------------------
# Step 1 — Cross-compile inside Docker
# ---------------------------------------------------------------------------
echo "==> [1/3] Docker cross-compile for aarch64..."

mkdir -p "${OUT_DIR}"

# ubuntu:22.04 with g++-aarch64-linux-gnu produces a glibc-2.35 binary,
# which matches Raspberry Pi OS Bookworm (glibc 2.35 / aarch64).
docker run --rm \
  -v "${REPO_ROOT}:/repo" \
  ubuntu:22.04 \
  bash -c "
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
      cmake make \
      g++-aarch64-linux-gnu \
      > /dev/null

    BUILD=/tmp/nfc-build-pi
    rm -rf \"\${BUILD}\"
    mkdir -p \"\${BUILD}\"

    cmake -B \"\${BUILD}\" \
      -DCMAKE_TOOLCHAIN_FILE=/repo/projects/CardputerZero-Emulator/cmake/aarch64-linux-gnu.cmake \
      -DEMU_SKIP_APPLAUNCH=ON \
      -DCMAKE_BUILD_TYPE=Release \
      /repo/projects/CardputerZero-Emulator

    cmake --build \"\${BUILD}\" --target nfc-usb-test -j\$(nproc)

    aarch64-linux-gnu-strip \"\${BUILD}/nfc-usb-test\"
    cp \"\${BUILD}/nfc-usb-test\" /repo/projects/CardputerZero-Emulator/build-pi/nfc-usb-test
  "

echo "==> [1/3] Built: ${OUT_DIR}/nfc-usb-test"
file "${OUT_DIR}/nfc-usb-test"

# ---------------------------------------------------------------------------
# Step 2 — Deploy to device
# ---------------------------------------------------------------------------
echo ""
echo "==> [2/3] Deploying to ${DEVICE_USER}@${DEVICE_HOST}:${DEPLOY_PATH}/..."

if command -v sshpass >/dev/null 2>&1; then
  _SSH() { sshpass -p "${DEVICE_PASS}" ssh -o StrictHostKeyChecking=no "$@"; }
  _SCP() { sshpass -p "${DEVICE_PASS}" scp -o StrictHostKeyChecking=no "$@"; }
else
  echo "    (sshpass not found — install via 'brew install sshpass' to skip password prompt)"
  _SSH() { ssh "$@"; }
  _SCP() { scp "$@"; }
fi

_SSH "${DEVICE_USER}@${DEVICE_HOST}" "mkdir -p '${DEPLOY_PATH}'"
_SCP "${OUT_DIR}/nfc-usb-test" "${DEVICE_USER}@${DEVICE_HOST}:${DEPLOY_PATH}/nfc-usb-test"
_SSH "${DEVICE_USER}@${DEVICE_HOST}" "chmod +x '${DEPLOY_PATH}/nfc-usb-test'"

# ---------------------------------------------------------------------------
# Step 3 — Verify on device
# ---------------------------------------------------------------------------
echo ""
echo "==> [3/3] Verifying on device..."
_SSH "${DEVICE_USER}@${DEVICE_HOST}" "file '${DEPLOY_PATH}/nfc-usb-test'"

echo ""
echo "==> Done. Run on device:"
echo "    ${DEPLOY_PATH}/nfc-usb-test /dev/ttyUSB0"
echo "    ${DEPLOY_PATH}/nfc-usb-test /dev/ttyACM0"
