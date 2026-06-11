#!/usr/bin/env bash
# ============================================================================
# deploy.sh — Build and deploy APPLaunch only
#
# Usage:
#   ./deploy.sh deploy [host] [user] [pass]    Deploy to device (default)
#   ./deploy.sh build                           Build APPLaunch locally
#   ./deploy.sh all [host] [user] [pass]       Build + deploy
#
# Env:
#   SKIP_BUILD=1        Skip local compilation
#   BUILD_JOBS=8        Override parallel jobs
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APPL_ROOT="${REPO_ROOT}/projects/APPLaunch"
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
# build_all — compile APPLaunch
# ═══════════════════════════════════════════════════════════════════════════════
build_all() {
  info "Building APPLaunch..."
  cd "${APPL_ROOT}"
  rm -rf build
  CardputerZero=y "${SCONS[@]}" -j"${BUILD_JOBS}"
  [[ -f dist/M5CardputerZero-APPLaunch ]] || { err "APPLaunch build failed"; exit 1; }
  info "APPLaunch OK  $(ls -lh dist/M5CardputerZero-APPLaunch | awk '{print $5}')"
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

  info "Installing and restarting ${SERVICE}..."
  _SSH "${user}@${host}" "
    set -e
    echo '${pass}' | sudo -S systemctl stop '${SERVICE}'
    echo '${pass}' | sudo -S mkdir -p '${app_root}/bin'
    [[ -f '${stage}/M5CardputerZero-APPLaunch' ]] && echo '${pass}' | sudo -S install -m 755 '${stage}/M5CardputerZero-APPLaunch' '${app_root}/bin/'
    echo '${pass}' | sudo -S systemctl start '${SERVICE}'
    sleep 1
    systemctl is-active '${SERVICE}'
  "
  info "Deploy done. ${SERVICE} active on ${host}"
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
  all)
    if [[ "${SKIP_BUILD:-0}" != "1" ]]; then build_all; fi
    DEV_HOST="${1:-192.168.20.113}"
    deploy_files "${DEV_HOST}" "${2:-pi}" "${3:-pi}"
    ;;
  *)
    echo "Usage: $0 {build|deploy [host] [user] [pass]|all [host] [user] [pass]}"
    echo "  build    - compile APPLaunch"
    echo "  deploy   - SCP to device and restart service"
    echo "  all      - build + deploy"
    exit 1
    ;;
esac
