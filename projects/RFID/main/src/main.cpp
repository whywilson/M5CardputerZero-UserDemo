#include "lvgl/lvgl.h"
#include "../../../APPLaunch/main/ui/components/nfc/nfc_device_service.hpp"

extern "C" {
#include "../../../APPLaunch/main/hal/hal_paths.h"
}

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <csignal>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#if LV_USE_SDL
#include "lvgl/src/drivers/sdl/lv_sdl_keyboard.h"
#include "lvgl/src/drivers/sdl/lv_sdl_mouse.h"
#include "lvgl/src/drivers/sdl/lv_sdl_window.h"
#endif

#if LV_USE_LINUX_FBDEV
#include "lvgl/src/drivers/display/fb/lv_linux_fbdev.h"
#endif

#if LV_USE_LINUX_DRM
#include "lvgl/src/drivers/display/drm/lv_linux_drm.h"
#endif

#if LV_USE_EVDEV
#include "lvgl/src/drivers/evdev/lv_evdev.h"
#endif

namespace {

volatile sig_atomic_t g_quit_requested = 0;

enum class PendingOp {
    None,
    Scan,
    Dump,
};

struct RfidReadUi {
    nfc_app::NfcDeviceService service;
    lv_obj_t *tabview = nullptr;
    lv_obj_t *endpoint_label = nullptr;
    lv_obj_t *status_label = nullptr;
    lv_obj_t *log_label = nullptr;
    lv_obj_t *saved_list_label = nullptr;
    lv_obj_t *emu_label = nullptr;
    lv_obj_t *tools_label = nullptr;
    lv_timer_t *timer = nullptr;
    std::vector<std::string> log_lines;
    std::vector<nfc_app::SavedRecord> saved_records;
    std::vector<nfc_app::MifareKeyRecord> mifare_keys;
    std::vector<nfc_app::NfcDeviceService::MfkeyResult> mfkey_results;
    int saved_index = 0;
    int mifare_key_index = 0;
    int mfkey_result_index = 0;
    PendingOp pending_op = PendingOp::None;
    bool scan_was_running = false;
    bool emu_probe_was_running = false;
    bool emu_dump_was_running = false;
    bool mfkey_was_running = false;
    bool emu_start_result_seen = false;
};

constexpr uint32_t CTRL_S = 0x13; // ASCII Ctrl+S
constexpr uint32_t CTRL_L = 0x0C; // ASCII Ctrl+L

enum class ShortcutTab {
    Read = 0,
    Saved = 1,
    Emu = 2,
    Tools = 3,
};

const char *getenv_default(const char *name, const char *fallback)
{
    const char *value = std::getenv(name);
    return value ? value : fallback;
}

void configure_rfid_storage_paths()
{
    const char *base_dir = std::getenv("M5CZ_RFID_APP_DIR");
    if (!base_dir || !base_dir[0]) {
        if (::access("/usr/share/APPLaunch/apps/rfid", F_OK) == 0) {
            base_dir = "/usr/share/APPLaunch/apps/rfid";
        } else {
            base_dir = ".";
        }
    }

    std::string root = std::string(base_dir) + "/nfc_data";
    std::string records = std::string(base_dir) + "/share/nfc/records";
    std::string keys = std::string(base_dir) + "/share/nfc/keys";
    setenv("M5CZ_NFC_ROOT_DIR", root.c_str(), 1);
    setenv("M5CZ_NFC_RECORDS_DIR", records.c_str(), 1);
    setenv("M5CZ_NFC_KEYS_DIR", keys.c_str(), 1);
}

void on_signal(int)
{
    g_quit_requested = 1;
}

int get_st7789v_fbdev(char *dev_path, size_t buf_size)
{
    if (!dev_path || buf_size == 0) return -1;

    FILE *fp = std::fopen("/proc/fb", "r");
    if (!fp) return -1;

    char line[256] = {0};
    int fb_num = -1;

    while (std::fgets(line, sizeof(line), fp)) {
        if (std::strstr(line, "fb_st7789v") && std::sscanf(line, "%d", &fb_num) == 1) {
            break;
        }
    }
    std::fclose(fp);

    if (fb_num < 0) return -1;
    std::snprintf(dev_path, buf_size, "/dev/fb%d", fb_num);
    return 0;
}

void init_display()
{
#if LV_USE_LINUX_FBDEV
    const char *device = std::getenv("LV_LINUX_FBDEV_DEVICE");
    char fbdev[64] = {0};
    if (!device && get_st7789v_fbdev(fbdev, sizeof(fbdev)) == 0) {
        device = fbdev;
    }
    if (!device) device = "/dev/fb0";

    lv_display_t *disp = lv_linux_fbdev_create();
    if (!disp) return;
    lv_linux_fbdev_set_file(disp, device);
#elif LV_USE_LINUX_DRM
    const char *device = getenv_default("LV_LINUX_DRM_CARD", "/dev/dri/card0");
    lv_display_t *disp = lv_linux_drm_create();
    if (!disp) return;
    lv_linux_drm_set_file(disp, device, -1);
#elif LV_USE_SDL
    const int width = std::atoi(getenv_default("LV_SDL_VIDEO_WIDTH", "320"));
    const int height = std::atoi(getenv_default("LV_SDL_VIDEO_HEIGHT", "170"));
    lv_sdl_window_create(width, height);
#else
#error Unsupported display backend
#endif
}

void init_input()
{
#if LV_USE_SDL
    lv_sdl_mouse_create();
    lv_sdl_keyboard_create();
#endif

#if LV_USE_EVDEV
    const char *mouse_device = std::getenv("LV_LINUX_MOUSE_DEVICE");
    const char *keyboard_device = getenv_default(
        "LV_LINUX_KEYBOARD_DEVICE",
        "/dev/input/by-path/platform-3f804000.i2c-event");

    if (mouse_device && mouse_device[0]) {
        lv_evdev_create(LV_INDEV_TYPE_POINTER, mouse_device);
    }
    if (keyboard_device && keyboard_device[0]) {
        lv_evdev_create(LV_INDEV_TYPE_KEYPAD, keyboard_device);
    }
#endif
}

std::string compact_endpoint_path(const std::string &path)
{
    if (path.empty()) return "(no device)";
    if (path.size() <= 28) return path;
    return "..." + path.substr(path.size() - 25);
}

void refresh_log_label(RfidReadUi *ui)
{
    if (!ui || !ui->log_label) return;
    std::ostringstream oss;
    for (size_t i = 0; i < ui->log_lines.size(); ++i) {
        if (i) oss << "\n";
        oss << ui->log_lines[i];
    }
    lv_label_set_text(ui->log_label, oss.str().c_str());
}

void append_log(RfidReadUi *ui, const std::string &line)
{
    if (!ui || line.empty()) return;
    ui->log_lines.push_back(line);
    constexpr size_t kMaxLines = 14;
    if (ui->log_lines.size() > kMaxLines) {
        ui->log_lines.erase(ui->log_lines.begin(),
                            ui->log_lines.begin() + (ui->log_lines.size() - kMaxLines));
    }
    refresh_log_label(ui);
}

void set_status(RfidReadUi *ui, const std::string &text)
{
    if (!ui || !ui->status_label) return;
    lv_label_set_text(ui->status_label, text.c_str());
}

void refresh_endpoint_label(RfidReadUi *ui)
{
    if (!ui || !ui->endpoint_label) return;
    const auto endpoint = ui->service.current_endpoint();
    const auto conn = ui->service.connection_state();
    std::string text = std::string("Mode: ") + nfc_app::to_string(endpoint.kind)
        + "  Dev: " + compact_endpoint_path(endpoint.path)
        + "\nConn: " + (conn.connected ? conn.status : "Disconnected");
    lv_label_set_text(ui->endpoint_label, text.c_str());
}

std::string summarize_saved(const nfc_app::SavedRecord &record)
{
    std::string title = record.meta.display_name;
    if (title.empty()) title = record.tag.uid;
    if (title.empty()) title = record.meta.record_id;
    if (title.empty()) title = "(unnamed)";

    std::string created = record.meta.created_at;
    if (created.size() > 16) created.resize(16);

    return title + " [" + record.tag.tag_type + "] " + created;
}

void refresh_saved_list_label(RfidReadUi *ui)
{
    if (!ui || !ui->saved_list_label) return;

    if (ui->saved_records.empty()) {
        lv_label_set_text(ui->saved_list_label, "Saved: 0\n(no records)");
        return;
    }

    if (ui->saved_index < 0) ui->saved_index = 0;
    if (ui->saved_index >= static_cast<int>(ui->saved_records.size())) {
        ui->saved_index = static_cast<int>(ui->saved_records.size()) - 1;
    }

    std::ostringstream oss;
    oss << "Saved: " << ui->saved_records.size() << "\n";

    const int begin = std::max(0, ui->saved_index - 2);
    const int end = std::min(static_cast<int>(ui->saved_records.size()), begin + 5);
    for (int i = begin; i < end; ++i) {
        oss << (i == ui->saved_index ? "> " : "  ")
            << summarize_saved(ui->saved_records[static_cast<size_t>(i)]);
        if (i + 1 < end) oss << "\n";
    }

    lv_label_set_text(ui->saved_list_label, oss.str().c_str());
}

void refresh_saved_records(RfidReadUi *ui)
{
    if (!ui) return;
    ui->saved_records = ui->service.list_saved_records();
    if (ui->saved_records.empty()) {
        ui->saved_index = 0;
    } else if (ui->saved_index >= static_cast<int>(ui->saved_records.size())) {
        ui->saved_index = static_cast<int>(ui->saved_records.size()) - 1;
    }
    refresh_saved_list_label(ui);
}

void refresh_mifare_keys(RfidReadUi *ui)
{
    if (!ui) return;
    ui->mifare_keys = ui->service.list_mifare_keys();
    if (ui->mifare_keys.empty()) {
        ui->mifare_key_index = 0;
        return;
    }
    if (ui->mifare_key_index < 0) ui->mifare_key_index = 0;
    if (ui->mifare_key_index >= static_cast<int>(ui->mifare_keys.size())) {
        ui->mifare_key_index = static_cast<int>(ui->mifare_keys.size()) - 1;
    }
}

std::string current_protocol_text(const nfc_app::NfcDeviceService &service)
{
    return nfc_app::to_string(service.current_emulator_protocol());
}

bool switch_to_pn532killer_preferred_mode(RfidReadUi *ui)
{
    if (!ui) return false;
    auto endpoint = ui->service.current_endpoint();
    if (endpoint.kind == nfc_app::TransportKind::UsbSerial ||
        endpoint.kind == nfc_app::TransportKind::UartSerial) {
        return false;
    }

    for (int i = 0; i < 4; ++i) {
        std::string mode_status;
        ui->service.cycle_device_mode(&mode_status);
        endpoint = ui->service.current_endpoint();
        if ((endpoint.kind == nfc_app::TransportKind::UsbSerial ||
             endpoint.kind == nfc_app::TransportKind::UartSerial) &&
            !endpoint.path.empty()) {
            append_log(ui, "> Auto mode: " + mode_status);
            return true;
        }
    }
    return false;
}

void apply_pn532killer_slot_profile(RfidReadUi *ui, const char *action)
{
    if (!ui) return;
    const auto conn = ui->service.connection_state();
    if (!conn.connected || conn.device_kind != nfc_app::DeviceKind::PN532Killer) return;

    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    if (!ui->service.hw_switch_emu_slot_and_probe(protocol, slot)) {
        append_log(ui, std::string("ERR ") + action + ": switch busy");
        set_status(ui, "EMU switch busy");
        return;
    }
    append_log(ui, std::string("OK ") + action + ": "
        + current_protocol_text(ui->service) + " slot " + std::to_string(slot));
    set_status(ui, "EMU slot/protocol applied");
}

std::string scan_status_text(const nfc_app::SavedRecord &record)
{
    const std::string uid = record.tag.uid.empty() ? "-" : record.tag.uid;
    const std::string type = record.tag.tag_type.empty() ? "Unknown" : record.tag.tag_type;

    // ISO15693 cards should not display NFC-A identity fields like ATQA/SAK.
    if (record.tag.protocol == nfc_app::ProtocolKind::Iso15693) {
        return std::string("ISO15693 UID=") + uid + " [" + type + "]";
    }

    auto find_identity = [&](const char *key) -> std::string {
        if (!key || !*key) return "";
        std::string key_up(key);
        std::transform(key_up.begin(), key_up.end(), key_up.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        for (const auto &kv : record.tag.identity_fields) {
            std::string kk = kv.first;
            std::transform(kk.begin(), kk.end(), kk.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            if (kk == key_up) return kv.second;
        }
        return "";
    };

    const std::string atqa = find_identity("ATQA");
    const std::string sak = find_identity("SAK");
    std::string text = "UID=" + uid + " [" + type + "]";
    if (!atqa.empty() || !sak.empty()) {
        text += " ";
        if (!atqa.empty()) text += "ATQA=" + atqa;
        if (!atqa.empty() && !sak.empty()) text += " ";
        if (!sak.empty()) text += "SAK=" + sak;
    }
    return text;
}

void refresh_emu_label(RfidReadUi *ui)
{
    if (!ui || !ui->emu_label) return;

    const auto conn = ui->service.connection_state();
    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    const auto cached = ui->service.emu_slot_info(protocol, slot);

    std::ostringstream oss;
    oss << "Conn: " << (conn.connected ? conn.status : "Disconnected") << "\n";
    oss << "Mode: " << nfc_app::to_string(conn.endpoint.kind)
        << "  Proto: " << current_protocol_text(ui->service)
        << "  Slot: " << slot << "\n";

    switch (conn.device_kind) {
    case nfc_app::DeviceKind::NFCUnit:
        oss << "Dev: NFCUnit  Profile: " << ui->service.nfcunit_profile_label();
        break;
    case nfc_app::DeviceKind::GroveNFC:
        oss << "Dev: GroveNFC";
        break;
    case nfc_app::DeviceKind::PN532Killer:
        oss << "Dev: PN532Killer";
        break;
    case nfc_app::DeviceKind::PN532:
        oss << "Dev: PN532 (NDEF emu)";
        break;
    default:
        oss << "Dev: unsupported";
        break;
    }

    if (conn.endpoint.kind == nfc_app::TransportKind::I2cBus &&
        conn.device_kind == nfc_app::DeviceKind::GroveNFC) {
        oss << "\nTip: Mode+ to USB/UART for PN532Killer";
    }

    if (cached.dump_loaded) {
        oss << "\nCache: dump loaded";
        if (!cached.uid.empty()) oss << " UID=" << cached.uid;
    } else {
        oss << "\nCache: empty";
    }

    lv_label_set_text(ui->emu_label, oss.str().c_str());
}

std::string summarize_mfkey_result(const nfc_app::NfcDeviceService::MfkeyResult &result)
{
    char line[96] = {0};
    std::snprintf(line,
                  sizeof(line),
                  "UID:%08X s%02u%c key:%s",
                  result.uid,
                  static_cast<unsigned>(result.sector),
                  result.key_type == 0 ? 'A' : 'B',
                  result.key_hex.empty() ? "(none)" : result.key_hex.c_str());
    return line;
}

std::string derive_sniff_uid_hex(const nfc_app::ScanState &scan)
{
    std::string hex;
    for (char c : scan.last_record.tag.uid) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    if (hex.size() < 8) return "11223344";
    return hex.substr(0, 8);
}

void refresh_tools_label(RfidReadUi *ui)
{
    if (!ui || !ui->tools_label) return;

    std::ostringstream oss;
    oss << "Keys: " << ui->mifare_keys.size();
    if (!ui->mifare_keys.empty()) {
        if (ui->mifare_key_index < 0) ui->mifare_key_index = 0;
        if (ui->mifare_key_index >= static_cast<int>(ui->mifare_keys.size())) {
            ui->mifare_key_index = static_cast<int>(ui->mifare_keys.size()) - 1;
        }
        const auto &key = ui->mifare_keys[static_cast<size_t>(ui->mifare_key_index)];
        oss << "  [" << (ui->mifare_key_index + 1) << "/" << ui->mifare_keys.size() << "]"
            << "\n" << (key.enabled ? "ON " : "OFF ")
            << nfc_app::to_string(key.type) << " "
            << key.label << " " << key.key_hex;
    } else {
        oss << "\n(no mifare keys)";
    }

    oss << "\nMFKey: "
        << (ui->service.hw_mfkey_running() ? "running" : "idle")
        << " " << ui->service.hw_mfkey_progress() << "%"
        << "  Results: " << ui->mfkey_results.size();

    if (!ui->mfkey_results.empty()) {
        if (ui->mfkey_result_index < 0) ui->mfkey_result_index = 0;
        if (ui->mfkey_result_index >= static_cast<int>(ui->mfkey_results.size())) {
            ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
        }
        const auto &result = ui->mfkey_results[static_cast<size_t>(ui->mfkey_result_index)];
        oss << "\n[" << (ui->mfkey_result_index + 1) << "/" << ui->mfkey_results.size() << "] "
            << summarize_mfkey_result(result);
    }

    lv_label_set_text(ui->tools_label, oss.str().c_str());
}

void on_cycle_mode(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    std::string status;
    ui->service.cycle_device_mode(&status);
    append_log(ui, "> " + status);
    set_status(ui, status.empty() ? "Mode switched" : status);
    refresh_endpoint_label(ui);
}

void on_connect(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    switch_to_pn532killer_preferred_mode(ui);

    const bool ok = ui->service.connect_current();
    const auto conn = ui->service.connection_state();
    if (!ok) {
        append_log(ui, "ERR connect: " + conn.detail);
        set_status(ui, "Connect failed");
    } else {
        append_log(ui, "OK connect: " + conn.status);
        append_log(ui, "    " + conn.detail);
        set_status(ui, conn.status);
    }
    refresh_endpoint_label(ui);
    refresh_emu_label(ui);
    refresh_mifare_keys(ui);
    refresh_tools_label(ui);
}

void on_scan(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    if (!conn.connected) {
        set_status(ui, "Connect device first");
        append_log(ui, "ERR: not connected");
        return;
    }

    std::string err;
    bool ok = false;
    if (ui->service.is_current_device_uhf()) {
        ok = ui->service.start_uhf_scan_once(&err);
        append_log(ui, "> UHF inventory once...");
    } else {
        ok = ui->service.start_scan();
        append_log(ui, "> Scan card...");
    }

    if (!ok) {
        const auto state = ui->service.scan_state();
        if (err.empty()) err = state.error;
        if (err.empty()) err = "scan failed";
        append_log(ui, "ERR: " + err);
        set_status(ui, err);
        return;
    }
    set_status(ui, "Scanning...");
    ui->pending_op = PendingOp::Scan;
    ui->scan_was_running = true;
}

void on_dump(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    if (!ui->service.start_dump_last_scan()) {
        const auto scan = ui->service.scan_state();
        const std::string msg = scan.error.empty() ? scan.status : scan.error;
        append_log(ui, "ERR dump: " + msg);
        set_status(ui, msg.empty() ? "Dump failed" : msg);
        return;
    }
    append_log(ui, "> Dump card...");
    set_status(ui, "Dumping...");
    ui->pending_op = PendingOp::Dump;
    ui->scan_was_running = true;
}

void on_save(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    std::string err;
    if (!ui->service.save_last_scan(&err)) {
        if (err.empty()) err = "Save failed";
        append_log(ui, "ERR save: " + err);
        set_status(ui, err);
        return;
    }
    append_log(ui, "OK save: record stored");
    set_status(ui, "Saved");
    refresh_saved_records(ui);
}

void on_saved_prev(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->saved_records.empty()) return;
    ui->saved_index = (ui->saved_index - 1 + static_cast<int>(ui->saved_records.size()))
        % static_cast<int>(ui->saved_records.size());
    refresh_saved_list_label(ui);
}

void on_saved_next(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->saved_records.empty()) return;
    ui->saved_index = (ui->saved_index + 1) % static_cast<int>(ui->saved_records.size());
    refresh_saved_list_label(ui);
}

void on_saved_refresh(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    refresh_saved_records(ui);
}

void on_saved_delete(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    if (ui->saved_records.empty()) {
        append_log(ui, "ERR delete: no saved records");
        set_status(ui, "No saved records");
        return;
    }

    const auto &record = ui->saved_records[static_cast<size_t>(ui->saved_index)];
    std::string err;
    if (!ui->service.delete_saved_record(record.meta.record_id, &err)) {
        if (err.empty()) err = "Delete failed";
        append_log(ui, "ERR delete: " + err);
        set_status(ui, err);
        return;
    }

    append_log(ui, "OK delete: " + record.meta.record_id);
    set_status(ui, "Saved record deleted");
    refresh_saved_records(ui);
}

void on_clear_log(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    ui->log_lines.clear();
    refresh_log_label(ui);
    set_status(ui, "Log cleared");
}

void on_emu_protocol(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    if (conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
        ui->service.toggle_nfcunit_profile_protocol();
    } else {
        ui->service.cycle_hw_emu_protocol();
    }
    append_log(ui, "> EMU protocol: " + current_protocol_text(ui->service));
    apply_pn532killer_slot_profile(ui, "protocol");
    refresh_emu_label(ui);
}

void on_emu_slot_prev(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    ui->service.cycle_slot(-1);
    append_log(ui, "> EMU slot: " + std::to_string(ui->service.selected_slot_index()));
    apply_pn532killer_slot_profile(ui, "slot");
    refresh_emu_label(ui);
}

void on_emu_slot_next(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    ui->service.cycle_slot(1);
    append_log(ui, "> EMU slot: " + std::to_string(ui->service.selected_slot_index()));
    apply_pn532killer_slot_profile(ui, "slot");
    refresh_emu_label(ui);
}

void on_emu_start(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    if (!conn.connected) {
        append_log(ui, "ERR emu: connect device first");
        set_status(ui, "Connect device first");
        return;
    }

    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    std::string err;
    bool ok = false;

    if (conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
        ok = ui->service.start_nfcunit_current_profile_emulation_async();
        ui->emu_start_result_seen = false;
        if (!ok) err = "NFCUnit start already running";
    } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC) {
        ok = ui->service.grovenfc_activate(protocol, slot, &err);
    } else if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
        ok = ui->service.hw_switch_emu_slot_and_probe(protocol, slot);
        if (!ok) err = "Probe/start rejected";
    } else if (conn.device_kind == nfc_app::DeviceKind::PN532) {
        ok = ui->service.start_pn532_ndef_emulation("https://m5stack.com", &err);
    } else {
        err = "Current device does not support emulation";
    }

    if (!ok) {
        append_log(ui, "ERR emu start: " + err);
        set_status(ui, err.empty() ? "EMU start failed" : err);
    } else {
        append_log(ui, "OK emu start: " + current_protocol_text(ui->service)
            + " slot " + std::to_string(slot));
        set_status(ui, "EMU started");
    }
    refresh_emu_label(ui);
}

void on_emu_stop(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    bool ok = false;

    if (conn.device_kind == nfc_app::DeviceKind::PN532) {
        ui->service.stop_pn532_ndef_emulation();
        ok = true;
    } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
               conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
        ok = ui->service.grovenfc_deactivate();
    } else if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
        ui->service.hw_switch_to_reader_mode();
        ok = true;
    }

    if (ok) {
        append_log(ui, "OK emu stop");
        set_status(ui, "EMU stopped");
    } else {
        append_log(ui, "ERR emu stop: unsupported or failed");
        set_status(ui, "EMU stop failed");
    }
    refresh_emu_label(ui);
}

void on_emu_probe(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    std::string err;
    bool ok = false;

    if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
        ok = ui->service.hw_switch_emu_slot_and_probe(protocol, slot);
        if (!ok) err = "probe busy";
    } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
               conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
        ok = ui->service.cache_i2c_slot_dump(protocol, slot, &err);
    } else {
        err = "Probe available on PN532Killer/I2C emu only";
    }

    if (!ok) {
        append_log(ui, "ERR emu probe: " + err);
        set_status(ui, err.empty() ? "Probe failed" : err);
    } else {
        append_log(ui, "OK emu probe slot " + std::to_string(slot));
        set_status(ui, "Probe done");
    }
    refresh_emu_label(ui);
}

void on_emu_dump(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto conn = ui->service.connection_state();
    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    std::string err;
    bool ok = false;

    if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
        ok = ui->service.hw_start_emu_dump_async(protocol, slot);
        if (!ok) err = "dump busy";
    } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
               conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
        ok = ui->service.cache_i2c_slot_dump(protocol, slot, &err);
    } else {
        err = "Dump available on PN532Killer/I2C emu only";
    }

    if (!ok) {
        append_log(ui, "ERR emu dump: " + err);
        set_status(ui, err.empty() ? "Dump failed" : err);
    } else {
        append_log(ui, "> EMU dump slot " + std::to_string(slot));
        set_status(ui, "Dump in progress");
    }
    refresh_emu_label(ui);
}

void on_emu_save_dump(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const auto protocol = ui->service.current_emulator_protocol();
    const int slot = ui->service.selected_slot_index();
    std::string err;
    if (!ui->service.save_emu_dump_cached(protocol, slot, &err)) {
        if (err.empty()) err = "No cached dump";
        append_log(ui, "ERR save dump: " + err);
        set_status(ui, err);
        return;
    }

    append_log(ui, "OK save dump: slot " + std::to_string(slot));
    set_status(ui, "EMU dump saved");
    refresh_saved_records(ui);
}

void on_tools_key_prev(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->mifare_keys.empty()) return;
    ui->mifare_key_index = (ui->mifare_key_index - 1 + static_cast<int>(ui->mifare_keys.size()))
        % static_cast<int>(ui->mifare_keys.size());
    refresh_tools_label(ui);
}

void on_tools_key_next(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->mifare_keys.empty()) return;
    ui->mifare_key_index = (ui->mifare_key_index + 1) % static_cast<int>(ui->mifare_keys.size());
    refresh_tools_label(ui);
}

void on_tools_key_toggle(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->mifare_keys.empty()) return;

    std::string err;
    if (!ui->service.toggle_mifare_key_enabled(ui->mifare_key_index, &err)) {
        append_log(ui, "ERR key toggle: " + err);
        set_status(ui, err.empty() ? "Toggle key failed" : err);
        return;
    }

    append_log(ui, "OK key toggle");
    set_status(ui, "Key toggled");
    refresh_mifare_keys(ui);
    refresh_tools_label(ui);
}

void on_tools_reload(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;
    refresh_mifare_keys(ui);
    ui->mfkey_results = ui->service.hw_mfkey_results();
    if (ui->mfkey_results.empty()) ui->mfkey_result_index = 0;
    if (!ui->mfkey_results.empty()) {
        ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
    }
    append_log(ui, "OK tools reload");
    refresh_tools_label(ui);
}

void on_tools_mfkey_start(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
    if (ui->service.hw_sniff_set_uid(uid_hex)) {
        append_log(ui, "> Sniff UID set: " + uid_hex);
    }

    if (!ui->service.hw_start_mfkey_async(false)) {
        append_log(ui, "ERR mfkey: already running");
        set_status(ui, "MFKey already running");
        return;
    }
    append_log(ui, "> MFKey crack start");
    set_status(ui, "MFKey running");
    refresh_tools_label(ui);
}

void on_tools_mfkey64_start(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
    if (ui->service.hw_sniff_set_uid(uid_hex)) {
        append_log(ui, "> Sniff UID set: " + uid_hex);
    }

    if (!ui->service.hw_start_mfkey_async(true)) {
        append_log(ui, "ERR mfkey64: already running");
        set_status(ui, "MFKey64 already running");
        return;
    }
    append_log(ui, "> MFKey64 crack start");
    set_status(ui, "MFKey64 running");
    refresh_tools_label(ui);
}

void on_tools_set_uid(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
    if (!ui->service.hw_sniff_set_uid(uid_hex)) {
        append_log(ui, "ERR set uid: device not ready");
        set_status(ui, "Set UID failed");
        return;
    }
    append_log(ui, "OK sniff UID: " + uid_hex);
    set_status(ui, "Sniff UID updated");
}

void on_tools_import_result(lv_event_t *e)
{
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui || ui->mfkey_results.empty()) {
        append_log(ui, "ERR import: no mfkey result");
        set_status(ui, "No MFKey result");
        return;
    }

    if (ui->mfkey_result_index < 0) ui->mfkey_result_index = 0;
    if (ui->mfkey_result_index >= static_cast<int>(ui->mfkey_results.size())) {
        ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
    }

    std::string err;
    const auto &result = ui->mfkey_results[static_cast<size_t>(ui->mfkey_result_index)];
    if (!ui->service.import_mfkey_result(result, &err)) {
        append_log(ui, "ERR import: " + err);
        set_status(ui, err.empty() ? "Import failed" : err);
        return;
    }

    append_log(ui, "OK import: " + summarize_mfkey_result(result));
    set_status(ui, "MFKey imported");
    refresh_mifare_keys(ui);
    refresh_tools_label(ui);
}

ShortcutTab active_tab(const RfidReadUi *ui)
{
    if (!ui || !ui->tabview) return ShortcutTab::Read;
    const uint32_t idx = lv_tabview_get_tab_active(ui->tabview);
    switch (idx) {
    case 1: return ShortcutTab::Saved;
    case 2: return ShortcutTab::Emu;
    case 3: return ShortcutTab::Tools;
    default: return ShortcutTab::Read;
    }
}

void shortcut_read_tab(RfidReadUi *ui, uint32_t key)
{
    if (!ui) return;
    if (key == CTRL_S) {
        std::string err;
        if (!ui->service.save_last_scan(&err)) {
            if (err.empty()) err = "Save failed";
            append_log(ui, "ERR save: " + err);
            set_status(ui, err);
            return;
        }
        append_log(ui, "OK save: record stored");
        set_status(ui, "Saved");
        refresh_saved_records(ui);
        return;
    }

    if (key == CTRL_L) {
        ui->log_lines.clear();
        refresh_log_label(ui);
        set_status(ui, "Log cleared");
        return;
    }

    switch (key) {
    case 'm':
    case 'M': {
        std::string status;
        ui->service.cycle_device_mode(&status);
        append_log(ui, "> " + status);
        set_status(ui, status.empty() ? "Mode switched" : status);
        refresh_endpoint_label(ui);
        break;
    }
    case 'c':
    case 'C': {
        switch_to_pn532killer_preferred_mode(ui);
        const bool ok = ui->service.connect_current();
        const auto conn = ui->service.connection_state();
        if (!ok) {
            append_log(ui, "ERR connect: " + conn.detail);
            set_status(ui, "Connect failed");
        } else {
            append_log(ui, "OK connect: " + conn.status);
            append_log(ui, "    " + conn.detail);
            set_status(ui, conn.status);
        }
        refresh_endpoint_label(ui);
        refresh_emu_label(ui);
        refresh_mifare_keys(ui);
        refresh_tools_label(ui);
        break;
    }
    case 's':
    case 'S':
    case 'r':
    case 'R': {
        const auto conn = ui->service.connection_state();
        if (!conn.connected) {
            set_status(ui, "Connect device first");
            append_log(ui, "ERR: not connected");
            break;
        }

        std::string err;
        bool ok = false;
        if (ui->service.is_current_device_uhf()) {
            ok = ui->service.start_uhf_scan_once(&err);
            append_log(ui, "> UHF inventory once...");
        } else {
            ok = ui->service.start_scan();
            append_log(ui, "> Scan card...");
        }

        if (!ok) {
            const auto state = ui->service.scan_state();
            if (err.empty()) err = state.error;
            if (err.empty()) err = "scan failed";
            append_log(ui, "ERR: " + err);
            set_status(ui, err);
            break;
        }
        set_status(ui, "Scanning...");
        ui->pending_op = PendingOp::Scan;
        ui->scan_was_running = true;
        break;
    }
    case 'd':
    case 'D': {
        if (!ui->service.start_dump_last_scan()) {
            const auto scan = ui->service.scan_state();
            const std::string msg = scan.error.empty() ? scan.status : scan.error;
            append_log(ui, "ERR dump: " + msg);
            set_status(ui, msg.empty() ? "Dump failed" : msg);
            break;
        }
        append_log(ui, "> Dump card...");
        set_status(ui, "Dumping...");
        ui->pending_op = PendingOp::Dump;
        ui->scan_was_running = true;
        break;
    }
    default:
        break;
    }
}

void shortcut_saved_tab(RfidReadUi *ui, uint32_t key)
{
    if (!ui) return;
    switch (key) {
    case LV_KEY_UP:
    case LV_KEY_LEFT:
    case 'f':
    case 'F':
        if (!ui->saved_records.empty()) {
            ui->saved_index = (ui->saved_index - 1 + static_cast<int>(ui->saved_records.size()))
                % static_cast<int>(ui->saved_records.size());
            refresh_saved_list_label(ui);
        }
        break;
    case LV_KEY_DOWN:
    case LV_KEY_RIGHT:
    case 'x':
    case 'X':
        if (!ui->saved_records.empty()) {
            ui->saved_index = (ui->saved_index + 1) % static_cast<int>(ui->saved_records.size());
            refresh_saved_list_label(ui);
        }
        break;
    case 'r':
    case 'R':
        refresh_saved_records(ui);
        break;
    case 'd':
    case 'D': {
        if (ui->saved_records.empty()) {
            append_log(ui, "ERR delete: no saved records");
            set_status(ui, "No saved records");
            break;
        }
        const auto &record = ui->saved_records[static_cast<size_t>(ui->saved_index)];
        std::string err;
        if (!ui->service.delete_saved_record(record.meta.record_id, &err)) {
            if (err.empty()) err = "Delete failed";
            append_log(ui, "ERR delete: " + err);
            set_status(ui, err);
            break;
        }
        append_log(ui, "OK delete: " + record.meta.record_id);
        set_status(ui, "Saved record deleted");
        refresh_saved_records(ui);
        break;
    }
    default:
        break;
    }
}

void shortcut_emu_tab(RfidReadUi *ui, uint32_t key)
{
    if (!ui) return;

    if (key == CTRL_S) {
        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        std::string err;
        if (!ui->service.save_emu_dump_cached(protocol, slot, &err)) {
            if (err.empty()) err = "No cached dump";
            append_log(ui, "ERR save dump: " + err);
            set_status(ui, err);
            return;
        }
        append_log(ui, "OK save dump: slot " + std::to_string(slot));
        set_status(ui, "EMU dump saved");
        refresh_saved_records(ui);
        return;
    }

    const auto conn = ui->service.connection_state();
    switch (key) {
    case 'p':
    case 'P': {
        if (conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            ui->service.toggle_nfcunit_profile_protocol();
        } else {
            ui->service.cycle_hw_emu_protocol();
        }
        append_log(ui, "> EMU protocol: " + current_protocol_text(ui->service));
        apply_pn532killer_slot_profile(ui, "protocol");
        refresh_emu_label(ui);
        break;
    }
    case 'f':
    case 'F':
        ui->service.cycle_slot(-1);
        append_log(ui, "> EMU slot: " + std::to_string(ui->service.selected_slot_index()));
        apply_pn532killer_slot_profile(ui, "slot");
        refresh_emu_label(ui);
        break;
    case 'x':
    case 'X':
        ui->service.cycle_slot(1);
        append_log(ui, "> EMU slot: " + std::to_string(ui->service.selected_slot_index()));
        apply_pn532killer_slot_profile(ui, "slot");
        refresh_emu_label(ui);
        break;
    case 's':
    case 'S': {
        if (!conn.connected) {
            append_log(ui, "ERR emu: connect device first");
            set_status(ui, "Connect device first");
            break;
        }

        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        std::string err;
        bool ok = false;

        if (conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            ok = ui->service.start_nfcunit_current_profile_emulation_async();
            ui->emu_start_result_seen = false;
            if (!ok) err = "NFCUnit start already running";
        } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC) {
            ok = ui->service.grovenfc_activate(protocol, slot, &err);
        } else if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
            ok = ui->service.hw_switch_emu_slot_and_probe(protocol, slot);
            if (!ok) err = "Probe/start rejected";
        } else if (conn.device_kind == nfc_app::DeviceKind::PN532) {
            ok = ui->service.start_pn532_ndef_emulation("https://m5stack.com", &err);
        } else {
            err = "Current device does not support emulation";
        }

        if (!ok) {
            append_log(ui, "ERR emu start: " + err);
            set_status(ui, err.empty() ? "EMU start failed" : err);
        } else {
            append_log(ui, "OK emu start: " + current_protocol_text(ui->service)
                + " slot " + std::to_string(slot));
            set_status(ui, "EMU started");
        }
        refresh_emu_label(ui);
        break;
    }
    case 'q':
    case 'Q': {
        bool ok = false;
        if (conn.device_kind == nfc_app::DeviceKind::PN532) {
            ui->service.stop_pn532_ndef_emulation();
            ok = true;
        } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
                   conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            ok = ui->service.grovenfc_deactivate();
        } else if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
            ui->service.hw_switch_to_reader_mode();
            ok = true;
        }
        if (ok) {
            append_log(ui, "OK emu stop");
            set_status(ui, "EMU stopped");
        } else {
            append_log(ui, "ERR emu stop: unsupported or failed");
            set_status(ui, "EMU stop failed");
        }
        refresh_emu_label(ui);
        break;
    }
    case 'c':
    case 'C': {
        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        std::string err;
        bool ok = false;
        if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
            ok = ui->service.hw_switch_emu_slot_and_probe(protocol, slot);
            if (!ok) err = "probe busy";
        } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
                   conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            ok = ui->service.cache_i2c_slot_dump(protocol, slot, &err);
        } else {
            err = "Probe available on PN532Killer/I2C emu only";
        }
        if (!ok) {
            append_log(ui, "ERR emu probe: " + err);
            set_status(ui, err.empty() ? "Probe failed" : err);
        } else {
            append_log(ui, "OK emu probe slot " + std::to_string(slot));
            set_status(ui, "Probe done");
        }
        refresh_emu_label(ui);
        break;
    }
    case 'd':
    case 'D': {
        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        std::string err;
        bool ok = false;
        if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
            ok = ui->service.hw_start_emu_dump_async(protocol, slot);
            if (!ok) err = "dump busy";
        } else if (conn.device_kind == nfc_app::DeviceKind::GroveNFC ||
                   conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            ok = ui->service.cache_i2c_slot_dump(protocol, slot, &err);
        } else {
            err = "Dump available on PN532Killer/I2C emu only";
        }
        if (!ok) {
            append_log(ui, "ERR emu dump: " + err);
            set_status(ui, err.empty() ? "Dump failed" : err);
        } else {
            append_log(ui, "> EMU dump slot " + std::to_string(slot));
            set_status(ui, "Dump in progress");
        }
        refresh_emu_label(ui);
        break;
    }
    default:
        break;
    }
}

void shortcut_tools_tab(RfidReadUi *ui, uint32_t key)
{
    if (!ui) return;
    switch (key) {
    case 'f':
    case 'F':
        if (!ui->mifare_keys.empty()) {
            ui->mifare_key_index = (ui->mifare_key_index - 1 + static_cast<int>(ui->mifare_keys.size()))
                % static_cast<int>(ui->mifare_keys.size());
            refresh_tools_label(ui);
        }
        break;
    case 'x':
    case 'X':
        if (!ui->mifare_keys.empty()) {
            ui->mifare_key_index = (ui->mifare_key_index + 1) % static_cast<int>(ui->mifare_keys.size());
            refresh_tools_label(ui);
        }
        break;
    case 't':
    case 'T': {
        if (ui->mifare_keys.empty()) break;
        std::string err;
        if (!ui->service.toggle_mifare_key_enabled(ui->mifare_key_index, &err)) {
            append_log(ui, "ERR key toggle: " + err);
            set_status(ui, err.empty() ? "Toggle key failed" : err);
            break;
        }
        append_log(ui, "OK key toggle");
        set_status(ui, "Key toggled");
        refresh_mifare_keys(ui);
        refresh_tools_label(ui);
        break;
    }
    case 'r':
    case 'R':
        refresh_mifare_keys(ui);
        ui->mfkey_results = ui->service.hw_mfkey_results();
        if (ui->mfkey_results.empty()) ui->mfkey_result_index = 0;
        if (!ui->mfkey_results.empty()) ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
        append_log(ui, "OK tools reload");
        refresh_tools_label(ui);
        break;
    case 'c':
    case 'C': {
        const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
        if (ui->service.hw_sniff_set_uid(uid_hex)) {
            append_log(ui, "> Sniff UID set: " + uid_hex);
        }
        if (!ui->service.hw_start_mfkey_async(false)) {
            append_log(ui, "ERR mfkey: already running");
            set_status(ui, "MFKey already running");
            break;
        }
        append_log(ui, "> MFKey crack start");
        set_status(ui, "MFKey running");
        refresh_tools_label(ui);
        break;
    }
    case '6': {
        const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
        if (ui->service.hw_sniff_set_uid(uid_hex)) {
            append_log(ui, "> Sniff UID set: " + uid_hex);
        }
        if (!ui->service.hw_start_mfkey_async(true)) {
            append_log(ui, "ERR mfkey64: already running");
            set_status(ui, "MFKey64 already running");
            break;
        }
        append_log(ui, "> MFKey64 crack start");
        set_status(ui, "MFKey64 running");
        refresh_tools_label(ui);
        break;
    }
    case 'u':
    case 'U': {
        const std::string uid_hex = derive_sniff_uid_hex(ui->service.scan_state());
        if (!ui->service.hw_sniff_set_uid(uid_hex)) {
            append_log(ui, "ERR set uid: device not ready");
            set_status(ui, "Set UID failed");
            break;
        }
        append_log(ui, "OK sniff UID: " + uid_hex);
        set_status(ui, "Sniff UID updated");
        break;
    }
    case 'i':
    case 'I': {
        if (ui->mfkey_results.empty()) {
            append_log(ui, "ERR import: no mfkey result");
            set_status(ui, "No MFKey result");
            break;
        }
        if (ui->mfkey_result_index < 0) ui->mfkey_result_index = 0;
        if (ui->mfkey_result_index >= static_cast<int>(ui->mfkey_results.size())) {
            ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
        }
        std::string err;
        const auto &result = ui->mfkey_results[static_cast<size_t>(ui->mfkey_result_index)];
        if (!ui->service.import_mfkey_result(result, &err)) {
            append_log(ui, "ERR import: " + err);
            set_status(ui, err.empty() ? "Import failed" : err);
            break;
        }
        append_log(ui, "OK import: " + summarize_mfkey_result(result));
        set_status(ui, "MFKey imported");
        refresh_mifare_keys(ui);
        refresh_tools_label(ui);
        break;
    }
    default:
        break;
    }
}

void on_global_key(lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_KEY) return;
    auto *ui = static_cast<RfidReadUi *>(lv_event_get_user_data(e));
    if (!ui) return;

    const uint32_t key = lv_event_get_key(e);
    switch (active_tab(ui)) {
    case ShortcutTab::Read:
        shortcut_read_tab(ui, key);
        break;
    case ShortcutTab::Saved:
        shortcut_saved_tab(ui, key);
        break;
    case ShortcutTab::Emu:
        shortcut_emu_tab(ui, key);
        break;
    case ShortcutTab::Tools:
        shortcut_tools_tab(ui, key);
        break;
    }
}

void on_timer(lv_timer_t *timer)
{
    auto *ui = static_cast<RfidReadUi *>(lv_timer_get_user_data(timer));
    if (!ui) return;

    for (const auto &line : ui->service.drain_pending_log()) {
        append_log(ui, line);
    }

    const auto scan = ui->service.scan_state();
    if (ui->scan_was_running && !scan.running) {
        if (ui->pending_op == PendingOp::Dump) {
            if (scan.error.empty()) {
                append_log(ui, "OK dump: " + std::to_string(scan.last_record.tag.raw_data.size()) + " lines");
                set_status(ui, "Dump complete");
            } else {
                append_log(ui, "ERR dump: " + scan.error);
                set_status(ui, scan.error);
            }
        } else if (scan.has_result) {
            append_log(ui, "OK scan: " + scan.last_record.tag.uid + " [" + scan.last_record.tag.tag_type + "]");
            set_status(ui, scan_status_text(scan.last_record));
        } else {
            const std::string msg = scan.error.empty() ? scan.status : scan.error;
            append_log(ui, "ERR: " + msg);
            set_status(ui, msg.empty() ? "Scan failed" : msg);
        }
        ui->pending_op = PendingOp::None;
    }
    ui->scan_was_running = scan.running;

    const bool probe_running = ui->service.emu_probe_running();
    if (ui->emu_probe_was_running && !probe_running) {
        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        const auto cached = ui->service.emu_slot_info(protocol, slot);
        const auto probe_err = ui->service.emu_probe_error();
        if (!probe_err.empty()) {
            append_log(ui, "ERR emu probe: " + probe_err);
            set_status(ui, probe_err);
        } else {
            std::string msg = "OK emu probe done";
            if (!cached.uid.empty()) msg += " UID=" + cached.uid;
            append_log(ui, msg);
            set_status(ui, "EMU probe done");
        }
    }
    ui->emu_probe_was_running = probe_running;

    const bool dump_running = ui->service.emu_dump_running();
    if (ui->emu_dump_was_running && !dump_running) {
        const auto protocol = ui->service.current_emulator_protocol();
        const int slot = ui->service.selected_slot_index();
        if (ui->service.emu_dump_loaded(protocol, slot)) {
            append_log(ui, "OK emu dump loaded");
            set_status(ui, "EMU dump ready");
        } else {
            append_log(ui, "ERR emu dump failed");
            set_status(ui, "EMU dump failed");
        }
    }
    ui->emu_dump_was_running = dump_running;

    const auto emu_start = ui->service.nfcunit_emu_start_state();
    if (emu_start.running) {
        ui->emu_start_result_seen = false;
    } else if (emu_start.has_result && !ui->emu_start_result_seen) {
        if (emu_start.ok) {
            append_log(ui, "OK nfcunit emu: " + emu_start.profile);
            set_status(ui, "NFCUnit emu running");
        } else {
            std::string msg = emu_start.error.empty() ? "start failed" : emu_start.error;
            append_log(ui, "ERR nfcunit emu: " + msg);
            set_status(ui, msg);
        }
        ui->emu_start_result_seen = true;
    }

    const bool mfkey_running = ui->service.hw_mfkey_running();
    if (ui->mfkey_was_running && !mfkey_running) {
        ui->mfkey_results = ui->service.hw_mfkey_results();
        if (ui->mfkey_results.empty()) {
            ui->mfkey_result_index = 0;
            append_log(ui, "ERR mfkey: no key found");
            set_status(ui, "MFKey finished (no result)");
        } else {
            ui->mfkey_result_index = static_cast<int>(ui->mfkey_results.size()) - 1;
            append_log(ui, "OK mfkey results: " + std::to_string(ui->mfkey_results.size()));
            append_log(ui, "    " + summarize_mfkey_result(ui->mfkey_results.back()));
            set_status(ui, "MFKey finished");
        }
    }
    ui->mfkey_was_running = mfkey_running;

    refresh_endpoint_label(ui);
    refresh_emu_label(ui);
    refresh_tools_label(ui);
}

lv_obj_t *create_button(lv_obj_t *parent,
                        const char *text,
                        lv_event_cb_t cb,
                        void *user_data,
                        lv_coord_t x,
                        lv_coord_t y,
                        lv_coord_t w = 72)
{
    lv_obj_t *btn = lv_button_create(parent);
    lv_obj_set_size(btn, w, 24);
    lv_obj_set_pos(btn, x, y);
    lv_obj_add_flag(btn, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    return btn;
}

void build_ui(RfidReadUi *ui)
{
    lv_obj_t *screen = lv_screen_active();
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x0F1217), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);

    lv_obj_t *header = lv_label_create(screen);
    lv_label_set_text(header, "RFID");
    lv_obj_set_style_text_font(header, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_color(header, lv_color_hex(0xE9EEF4), 0);
    lv_obj_set_pos(header, 8, 4);

    lv_obj_t *sub = lv_label_create(screen);
    lv_label_set_text(sub, "Phase2: READ pipeline migrated");
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x6E7781), 0);
    lv_obj_set_pos(sub, 70, 10);

    lv_obj_t *tabview = lv_tabview_create(screen);
    ui->tabview = tabview;
    lv_obj_set_size(tabview, 320, 140);
    lv_obj_set_pos(tabview, 0, 30);
    lv_obj_add_flag(tabview, LV_OBJ_FLAG_EVENT_BUBBLE);

    lv_obj_t *tab_read = lv_tabview_add_tab(tabview, "READ");
    lv_obj_t *tab_saved = lv_tabview_add_tab(tabview, "SAVED");
    lv_obj_t *tab_emu = lv_tabview_add_tab(tabview, "EMU");
    lv_obj_t *tab_tools = lv_tabview_add_tab(tabview, "TOOLS");
    lv_obj_add_flag(tab_read, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_add_flag(tab_saved, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_add_flag(tab_emu, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_add_flag(tab_tools, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_add_event_cb(screen, on_global_key, LV_EVENT_KEY, ui);

    ui->endpoint_label = lv_label_create(tab_read);
    lv_obj_set_style_text_font(ui->endpoint_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->endpoint_label, lv_color_hex(0xB8C0CC), 0);
    lv_obj_set_size(ui->endpoint_label, 304, LV_SIZE_CONTENT);
    lv_obj_set_pos(ui->endpoint_label, 6, 4);

    ui->status_label = lv_label_create(tab_read);
    lv_obj_set_style_text_font(ui->status_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->status_label, lv_color_hex(0x8FE388), 0);
    lv_obj_set_pos(ui->status_label, 6, 27);
    lv_label_set_text(ui->status_label, "Ready");

    create_button(tab_read, "Mode+", on_cycle_mode, ui, 6, 42, 46);
    create_button(tab_read, "Connect", on_connect, ui, 56, 42, 46);
    create_button(tab_read, "Scan", on_scan, ui, 106, 42, 46);
    create_button(tab_read, "Dump", on_dump, ui, 156, 42, 46);
    create_button(tab_read, "Save", on_save, ui, 206, 42, 46);
    create_button(tab_read, "Clear", on_clear_log, ui, 256, 42, 46);

    lv_obj_t *log_box = lv_obj_create(tab_read);
    lv_obj_set_pos(log_box, 6, 71);
    lv_obj_set_size(log_box, 304, 54);
    lv_obj_set_style_pad_all(log_box, 4, 0);
    lv_obj_set_style_bg_color(log_box, lv_color_hex(0x0A0D12), 0);
    lv_obj_set_style_border_color(log_box, lv_color_hex(0x2A313A), 0);

    ui->log_label = lv_label_create(log_box);
    lv_obj_set_style_text_font(ui->log_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->log_label, lv_color_hex(0xD5DCE3), 0);
    lv_label_set_long_mode(ui->log_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(ui->log_label, 296);
    lv_obj_align(ui->log_label, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_label_set_text(ui->log_label, "");

    ui->saved_list_label = lv_label_create(tab_saved);
    lv_obj_set_style_text_font(ui->saved_list_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->saved_list_label, lv_color_hex(0xD5DCE3), 0);
    lv_label_set_long_mode(ui->saved_list_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_size(ui->saved_list_label, 304, 90);
    lv_obj_set_pos(ui->saved_list_label, 6, 6);
    lv_label_set_text(ui->saved_list_label, "Saved: loading...");

    create_button(tab_saved, "Prev", on_saved_prev, ui, 6, 100, 72);
    create_button(tab_saved, "Next", on_saved_next, ui, 82, 100, 72);
    create_button(tab_saved, "Delete", on_saved_delete, ui, 158, 100, 72);
    create_button(tab_saved, "Refresh", on_saved_refresh, ui, 234, 100, 72);

    ui->emu_label = lv_label_create(tab_emu);
    lv_obj_set_style_text_font(ui->emu_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->emu_label, lv_color_hex(0xD5DCE3), 0);
    lv_label_set_long_mode(ui->emu_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_size(ui->emu_label, 304, 34);
    lv_obj_set_pos(ui->emu_label, 6, 6);
    lv_label_set_text(ui->emu_label, "EMU: loading...");

    create_button(tab_emu, "Proto", on_emu_protocol, ui, 6, 44, 72);
    create_button(tab_emu, "Slot-", on_emu_slot_prev, ui, 82, 44, 72);
    create_button(tab_emu, "Slot+", on_emu_slot_next, ui, 158, 44, 72);
    create_button(tab_emu, "Start", on_emu_start, ui, 234, 44, 72);
    create_button(tab_emu, "Stop", on_emu_stop, ui, 6, 72, 72);
    create_button(tab_emu, "Probe", on_emu_probe, ui, 82, 72, 72);
    create_button(tab_emu, "Dump", on_emu_dump, ui, 158, 72, 72);
    create_button(tab_emu, "Save", on_emu_save_dump, ui, 234, 72, 72);

    ui->tools_label = lv_label_create(tab_tools);
    lv_obj_set_style_text_font(ui->tools_label, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(ui->tools_label, lv_color_hex(0xD5DCE3), 0);
    lv_label_set_long_mode(ui->tools_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_size(ui->tools_label, 304, 62);
    lv_obj_set_pos(ui->tools_label, 6, 6);
    lv_label_set_text(ui->tools_label, "TOOLS: loading...");

    create_button(tab_tools, "Key-", on_tools_key_prev, ui, 6, 74, 72);
    create_button(tab_tools, "Key+", on_tools_key_next, ui, 82, 74, 72);
    create_button(tab_tools, "Toggle", on_tools_key_toggle, ui, 158, 74, 72);
    create_button(tab_tools, "Reload", on_tools_reload, ui, 234, 74, 72);
    create_button(tab_tools, "Crack", on_tools_mfkey_start, ui, 6, 102, 72);
    create_button(tab_tools, "MF64", on_tools_mfkey64_start, ui, 82, 102, 72);
    create_button(tab_tools, "Import", on_tools_import_result, ui, 158, 102, 72);
    create_button(tab_tools, "UID4", on_tools_set_uid, ui, 234, 102, 72);

    refresh_endpoint_label(ui);
    refresh_saved_records(ui);
    refresh_mifare_keys(ui);
    refresh_emu_label(ui);
    refresh_tools_label(ui);
    append_log(ui, "READ ready: use Mode+/Connect/Scan.");
}

} // namespace

int main()
{
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    configure_rfid_storage_paths();
    hal_paths_init(nullptr);

    lv_init();
    init_display();
    init_input();

    RfidReadUi ui;
    build_ui(&ui);
    ui.timer = lv_timer_create(on_timer, 200, &ui);

    while (!g_quit_requested) {
        lv_timer_handler();
        usleep(5000);
    }

    if (ui.timer) {
        lv_timer_delete(ui.timer);
        ui.timer = nullptr;
    }

    return 0;
}
