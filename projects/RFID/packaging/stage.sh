#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${STAGE:?STAGE is required}"
: "${INSTALL_PREFIX:?INSTALL_PREFIX is required}"
: "${APP_INSTALL_DIR:?APP_INSTALL_DIR is required}"

mkdir -p "$STAGE$APP_INSTALL_DIR"
install -m 0755 "dist/M5CardputerZero-RFID" "$STAGE$APP_INSTALL_DIR/M5CardputerZero-RFID"

mkdir -p "$STAGE$APP_INSTALL_DIR/share"
cp -a "share/." "$STAGE$APP_INSTALL_DIR/share/"

mkdir -p "$STAGE$INSTALL_PREFIX/applications"
install -m 0644 "applications/rfid.desktop" "$STAGE$INSTALL_PREFIX/applications/rfid.desktop"

mkdir -p "$STAGE$INSTALL_PREFIX/share/images"
install -m 0644 "share/images/ic_rfid.png" "$STAGE$INSTALL_PREFIX/share/images/ic_rfid.png"

mkdir -p "$STAGE$APP_INSTALL_DIR/nfc_data"
mkdir -p "$STAGE$APP_INSTALL_DIR/share/nfc/records"
mkdir -p "$STAGE$APP_INSTALL_DIR/share/nfc/keys"
