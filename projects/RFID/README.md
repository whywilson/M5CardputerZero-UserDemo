# RFID Independent App

This directory now contains the standalone RFID app project scaffold.

## Current status

- Phase 1 complete: independent app entry is buildable and launchable.
- Existing RFID scripts/tools remain in this directory for reuse.

## Build

```bash
cd projects/RFID
scons -j$(nproc)
```

Output binary:

- dist/M5CardputerZero-RFID

## Launcher integration

Desktop entry:

- applications/rfid.desktop

Exec path:

- /usr/share/APPLaunch/apps/rfid/M5CardputerZero-RFID

## Debian packaging (official layout)

This project now includes an official-style Debian packaging script:

- tools/package_deb.py

The script creates a package layout compatible with the APPLaunch guide:

- DEBIAN/control
- DEBIAN/postinst
- DEBIAN/prerm
- usr/share/APPLaunch/applications/rfid.desktop
- usr/share/APPLaunch/apps/rfid/M5CardputerZero-RFID
- usr/share/APPLaunch/apps/rfid/share/**
- usr/share/APPLaunch/share/images/ic_rfid.png

Build and package:

```bash
cd projects/RFID
scons -j$(nproc)
python3 tools/package_deb.py --maintainer "yourname <you@example.com>"
```

Output package:

- build/rfid_0.1-m5stack1_arm64.deb

Install on device:

```bash
scp build/rfid_0.1-m5stack1_arm64.deb pi@<device-ip>:/tmp/
ssh pi@<device-ip> "echo pi | sudo -S dpkg -i /tmp/rfid_0.1-m5stack1_arm64.deb"
```

## Publish to AppStore (czdev)

Follow the official publish flow:

```bash
czdev login
czdev publish --deb build/rfid_0.1-m5stack1_arm64.deb
```

Recommended before publish:

- Prepare icon: 100x100 PNG
- Prepare screenshots: 320x170 PNG
- Ensure package size < 100MB

If `dist/M5CardputerZero-RFID` is missing, you can let the script build it:

```bash
python3 tools/package_deb.py --build-if-missing --maintainer "yourname <you@example.com>"
```

## NFC migration status

NFC read/write stack is now shared between APPLaunch and RFID under:

- ../shared_nfc/nfc/

Both projects include this shared directory in their build scripts, and no
longer keep separate per-project NFC component copies.

RFID still keeps its own HAL paths implementation:

- main/hal/hal_paths.h
- main/hal/hal_paths_rfid.c
