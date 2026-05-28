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

- /usr/share/APPLaunch/bin/M5CardputerZero-RFID

## Debian packaging (official layout)

This project now includes an official-style Debian packaging script:

- tools/package_deb.py

The script creates a package layout compatible with the APPLaunch guide:

- DEBIAN/control
- DEBIAN/postinst
- DEBIAN/prerm
- usr/share/APPLaunch/applications/rfid.desktop
- usr/share/APPLaunch/bin/M5CardputerZero-RFID
- usr/share/APPLaunch/share/images/rfid.png

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

If `dist/M5CardputerZero-RFID` is missing, you can let the script build it:

```bash
python3 tools/package_deb.py --build-if-missing --maintainer "yourname <you@example.com>"
```

## Migration plan from APPLaunch NFC page

1. Extract NFC domain service from APPLaunch into reusable modules:
   - APPLaunch main/ui/components/nfc/nfc_device_service.hpp
   - APPLaunch main/ui/components/nfc/nfc_transport.hpp
   - APPLaunch main/ui/components/nfc/nfc_spi_device.hpp

2. Move READ tab features:
   - device connect/switch, scan, dump, log pipeline.

3. Move SAVED tab features:
   - record list/edit/delete, key file and slot upload/download.

4. Move EMU tab features:
   - PN532Killer slot probe/dump/upload and NFCUnit profile control.

5. Move TOOLS tab features:
   - uid write flow, mfkey32v2/mfkey64 workflow, script bridges in this project.

6. Replace placeholder tab content in main/src/main.cpp with migrated UI components.
