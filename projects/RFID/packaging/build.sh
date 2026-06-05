#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f "dist/M5CardputerZero-RFID" ]]; then
  CardputerZero=y CONFIG_REPO_AUTOMATION=y scons -j1
fi
