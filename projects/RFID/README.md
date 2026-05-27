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
