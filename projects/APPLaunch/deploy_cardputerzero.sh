#!/usr/bin/env bash
# ============================================================================
# deploy.sh — Build, deploy & package CardputerZero apps
#
# Usage:
#   ./deploy.sh deploy [host] [user] [pass]    Deploy to device (default)
#   ./deploy.sh build                           Build all binaries locally
#   ./deploy.sh package                         Build + create .deb
#   ./deploy.sh all [host] [user] [pass]       Build + deploy + package
#
# Env:
#   SKIP_BUILD=1        Skip local compilation
#   BUILD_JOBS=8        Override parallel jobs
#   RFID_ONLY=1         Only build RFID (skip APPLaunch)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RFID_ROOT="${REPO_ROOT}/projects/RFID"
APPL_ROOT="${REPO_ROOT}/projects/APPLaunch"
RFID_BIN="${RFID_ROOT}/dist/M5CardputerZero-RFID"
RFID_DESKTOP="${RFID_ROOT}/applications/rfid.desktop"
RFID_ICON="${SCRIPT_DIR}/APPLaunch/share/images/ic_rfid.png"
MFKEY_SRC="${RFID_ROOT}/main/tools/mfkey"
MFKEY_DIST="${RFID_ROOT}/dist_mfkey"
SERVICE="APPLaunch.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

detect_jobs() {
  command -v nproc >/dev/null 2>&1 && { nproc; return; }
  command -v sysctl >/dev/null 2>&1 && { sysctl -n hw.ncpu; return; }
  echo 4
}
BUILD_JOBS="${BUILD_JOBS:-$(detect_jobs)}"

# ── Toolchain setup ──────────────────────────────────────────────────────────
export PATH="/opt/homebrew/bin:$PATH"
if [[ "$(uname -s)" == "Darwin" ]]; then
  export CONFIG_DEFAULT_FILE="${CONFIG_DEFAULT_FILE:-mac_cross_cp0_config_defaults.mk}"
  export CONFIG_TOOLCHAIN_PATH="${CONFIG_TOOLCHAIN_PATH:-/opt/homebrew/bin}"
else
  export CONFIG_DEFAULT_FILE="${CONFIG_DEFAULT_FILE:-linux_x86_cross_cp0_config_defaults.mk}"
fi

if command -v scons >/dev/null 2>&1; then
  SCONS=(scons)
else
  SCONS=(python3 -m SCons)
fi

if command -v sshpass >/dev/null 2>&1; then
  _SSH() { sshpass -p "${DEVICE_PASS:-pi}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"; }
  _SCP() { sshpass -p "${DEVICE_PASS:-pi}" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"; }
else
  _SSH() { ssh "$@"; }
  _SCP() { scp "$@"; }
fi
cd "${REPO_ROOT}"

# ═══════════════════════════════════════════════════════════════════════════════
# build_all — compile RFID, APPLaunch and mfkey tools
# ═══════════════════════════════════════════════════════════════════════════════
build_all() {
  # RFID
  info "Building RFID..."
  cd "${RFID_ROOT}"
  rm -rf build
  CardputerZero=y "${SCONS[@]}" -j"${BUILD_JOBS}"
  [[ -f dist/M5CardputerZero-RFID ]] || { err "RFID build failed"; exit 1; }
  info "RFID OK  $(ls -lh dist/M5CardputerZero-RFID | awk '{print $5}')"

  # APPLaunch (unless RFID_ONLY)
  if [[ "${RFID_ONLY:-0}" != "1" ]]; then
    info "Building APPLaunch..."
    cd "${APPL_ROOT}"
    rm -rf build
    CardputerZero=y "${SCONS[@]}" -j"${BUILD_JOBS}"
    [[ -f dist/M5CardputerZero-APPLaunch ]] || { err "APPLaunch build failed"; exit 1; }
    info "APPLaunch OK  $(ls -lh dist/M5CardputerZero-APPLaunch | awk '{print $5}')"
  fi

  # mfkey tools
  if [[ ! -f "${MFKEY_DIST}/mfkey32v2" || ! -f "${MFKEY_DIST}/mfkey64" ]]; then
    info "Building mfkey tools..."
    mkdir -p "${MFKEY_DIST}"
    local cc=""
    for c in "/opt/homebrew/bin/aarch64-unknown-linux-gnu-gcc" aarch64-linux-gnu-gcc; do
      command -v "$c" >/dev/null 2>&1 || [[ ! -x "$c" ]] || { cc="$c"; break; }
    done
    if [[ -n "$cc" ]]; then
      local mfkey_srcs="${MFKEY_SRC}/crapto1/crapto1.c ${MFKEY_SRC}/crapto1/crypto1.c ${MFKEY_SRC}/crapto1/bucketsort.c ${MFKEY_SRC}/util_posix.c"
      "$cc" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey32v2" "${MFKEY_SRC}/mfkey32v2.c" ${mfkey_srcs} -lm -static && info "  mfkey32v2" || warn "  mfkey32v2 FAIL"
      "$cc" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey64"   "${MFKEY_SRC}/mfkey64.c"   ${mfkey_srcs} -lm -static && info "  mfkey64"   || warn "  mfkey64 FAIL"
    else
      warn "No cross-compiler, skip mfkey"
    fi
  else
    info "mfkey tools up-to-date"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# deploy_files — upload and install on device
# ═══════════════════════════════════════════════════════════════════════════════
deploy_files() {
  local host="${1:-192.168.20.113}" user="${2:-pi}" pass="${3:-pi}"
  local stage="/home/${user}/dist"
  local app_root="/usr/share/APPLaunch"

  info "Deploy to ${user}@${host} ..."

  _SSH "${user}@${host}" "mkdir -p '${stage}'"

  # APPLaunch
  if [[ -f "${APPL_ROOT}/dist/M5CardputerZero-APPLaunch" ]]; then
    _SCP "${APPL_ROOT}/dist/M5CardputerZero-APPLaunch" "${user}@${host}:${stage}/"
  fi

  # RFID + desktop + icon
  [[ -f "${RFID_BIN}" ]] && _SCP "${RFID_BIN}" "${user}@${host}:${stage}/"
  [[ -f "${RFID_DESKTOP}" ]] && _SCP "${RFID_DESKTOP}" "${user}@${host}:${stage}/"
  [[ -f "${RFID_ICON}" ]] && _SCP "${RFID_ICON}" "${user}@${host}:${stage}/"

  # mfkey
  [[ -f "${MFKEY_DIST}/mfkey32v2" ]] && _SCP "${MFKEY_DIST}/mfkey32v2" "${user}@${host}:${stage}/"
  [[ -f "${MFKEY_DIST}/mfkey64" ]] && _SCP "${MFKEY_DIST}/mfkey64" "${user}@${host}:${stage}/"

  info "Installing and restarting ${SERVICE}..."
  _SSH "${user}@${host}" "
    set -e
    echo '${pass}' | sudo -S systemctl stop '${SERVICE}'
    echo '${pass}' | sudo -S mkdir -p '${app_root}/bin' '${app_root}/applications' '${app_root}/share/images'
    [[ -f '${stage}/M5CardputerZero-APPLaunch' ]] && echo '${pass}' | sudo -S install -m 755 '${stage}/M5CardputerZero-APPLaunch' '${app_root}/bin/'
    [[ -f '${stage}/M5CardputerZero-RFID'     ]] && echo '${pass}' | sudo -S install -m 755 '${stage}/M5CardputerZero-RFID'     '${app_root}/bin/'
    [[ -f '${stage}/rfid.desktop'             ]] && echo '${pass}' | sudo -S install -m 644 '${stage}/rfid.desktop'             '${app_root}/applications/'
    [[ -f '${stage}/ic_rfid.png'              ]] && echo '${pass}' | sudo -S install -m 644 '${stage}/ic_rfid.png'              '${app_root}/share/images/'
    [[ -f '${stage}/mfkey32v2'               ]] && echo '${pass}' | sudo -S install -m 755 '${stage}/mfkey32v2'               '${app_root}/bin/'
    [[ -f '${stage}/mfkey64'                 ]] && echo '${pass}' | sudo -S install -m 755 '${stage}/mfkey64'                 '${app_root}/bin/'
    echo '${pass}' | sudo -S systemctl start '${SERVICE}'
    sleep 1
    systemctl is-active '${SERVICE}'
  "
  info "Deploy done. ${SERVICE} active on ${host}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# package_deb — create .deb with all built binaries
# ═══════════════════════════════════════════════════════════════════════════════
package_deb() {
  info "Packaging .deb..."
  cd "${RFID_ROOT}"
  if [[ -f "${APPL_ROOT}/dist/M5CardputerZero-APPLaunch" ]]; then
    mkdir -p dist_stage
    cp -f "${APPL_ROOT}/dist/M5CardputerZero-APPLaunch" dist_stage/
  fi
  python3 tools/package_deb.py --build-if-missing --revision "m5stack$(date +%Y%m%d)"
  local deb=$(ls -t build/rfid_*.deb 2>/dev/null | head -1)
  if [[ -n "$deb" ]]; then
    cp -f "$deb" "${REPO_ROOT}/"
    info "Package: ${REPO_ROOT}/$(basename $deb)"
  else
    err "deb packaging failed"
    exit 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
CMD="${1:-deploy}"
shift 2>/dev/null || true

case "${CMD}" in
  build)
    build_all
    ;;
  deploy)
    deploy_files "${1:-192.168.20.113}" "${2:-pi}" "${3:-pi}"
    ;;
  package)
    if [[ "${SKIP_BUILD:-0}" != "1" ]]; then build_all; fi
    package_deb
    ;;
  all)
    build_all
    DEV_HOST="${1:-192.168.20.113}"
    deploy_files "${DEV_HOST}" "${2:-pi}" "${3:-pi}"
    package_deb
    ;;
  *)
    echo "Usage: $0 {build|deploy [host] [user] [pass]|package|all [host] [user] [pass]}"
    echo "  build    - compile RFID + APPLaunch + mfkey"
    echo "  deploy   - SCP to device and restart service"
    echo "  package  - build + create .deb"
    echo "  all      - build + deploy + package"
    exit 1
    ;;
esac
